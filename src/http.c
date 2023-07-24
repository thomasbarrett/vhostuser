#define _GNU_SOURCE
#include <http.h>
#include <log.h>

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define TCP_ACCEPT_QUEUE_DEPTH 16

#define PARSE_INCOMPLETE -1
#define PARSE_ERROR -2

static const char* http_reason_phrase(int status) {
    switch (status) {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 203: return "Non-Authoritative Information";
        case 204: return "No Content";
        case 205: return "Reset Content";
        case 206: return "Partial Content";
        case 300: return "Multiple Choices";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 305: return "Use Proxy";
        case 307: return "Temporary Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 402: return "Payment Required";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 407: return "Proxy Authentication Required";
        case 408: return "Request Time-out";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Request Entity Too Large";
        case 414: return "Request-URI Too Large";
        case 415: return "Unsupported Media Type";
        case 416: return "Requested range not satisfiable";
        case 417: return "Expectation Failed";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Time-out";
        case 505: return "HTTP Version not supported";
        default: return "Unknown";
    }
}

static int parse_whitespace(const char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != ' ') return i;
    }

    return len;
}

static int parse_string(const char *buf, size_t len, const char *str) {
    for (size_t i = 0; i < len; i++) {
        if (str[i] == '\0') return i;
        if (buf[i] != str[i]) return PARSE_ERROR;
    }

    if (str[len] == '\0') return len;

    return PARSE_INCOMPLETE;
}

static int parse_char(const char *buf, size_t len, char c) {
    if (len == 0) return PARSE_INCOMPLETE;
    if (*buf != c) return PARSE_ERROR;

    return 1;
}

static int parse_token(const char *buf, size_t len, const char *delim, char *res, size_t res_len) {
    for (size_t i = 0; i < len; i++) {
        if (i == res_len) return PARSE_ERROR;
        if (strchr(delim, buf[i]) != NULL) return i;
        res[i] = buf[i];
    }

    return PARSE_INCOMPLETE;
}

static int parse_request_line(const char *buf, size_t len, http_request_t *request) {
    const char *iter = buf;
    const char *iter_end = buf + len;

    int res = parse_token(iter, iter_end - iter, " \r\n", request->method, HTTP_REQUEST_METHOD_LEN);
    if (res < 0) return res;
    iter += res;
    
    res = parse_char(iter, iter_end - iter, ' ');
    if (res < 0) return res;
    iter += res;

    res = parse_token(iter, iter_end - iter, " \r\n", request->uri, HTTP_REQUEST_URI_LEN);
    if (res < 0) return res;
    iter += res;

    res = parse_char(iter, iter_end - iter, ' ');
    if (res < 0) return res;
    iter += res;

    res = parse_token(iter, iter_end - iter, " \r\n", request->version, HTTP_REQUEST_VERSION_LEN);
    if (res < 0) return res;
    iter += res;

    res = parse_string(iter, iter_end - iter, "\r\n");
    if (res < 0) return res;
    iter += res;

    return iter - buf;
}

static int parse_header(const char *buf, size_t len, http_header_t *header) {
    const char *iter = buf;
    const char *iter_end = buf + len;

    int res = parse_token(iter, iter_end - iter, " \r\n:", header->name, HTTP_HEADER_KEY_LEN_MAX);
    if (res < 0) return res;
    iter += res;

    res = parse_char(iter, iter_end - iter, ':');
    if (res < 0) return res;
    iter += res;

    res = parse_whitespace(iter, iter_end - iter);
    if (res < 0) return res;
    iter += res;

    res = parse_token(iter, iter_end - iter, "\r\n", header->value, HTTP_HEADER_VAL_LEN_MAX);
    if (res < 0) return res;
    iter += res;

    res = parse_string(iter, iter_end - iter, "\r\n");
    if (res < 0) return res;
    iter += res;

    return iter - buf;
}

static int parse_request(const char *buf, size_t len, http_request_t *request) {
 const char *iter = buf;
    const char *iter_end = buf + len;

    int res = parse_request_line(iter, iter_end - iter, request);
    if (res < 0) {
        return res;
    }
    iter += res;
    
    for (size_t i = 0; i < HTTP_HEADER_COUNT_MAX; i++) {
        int res = parse_header(iter, iter_end - iter, &request->headers[i]);
        if (res == PARSE_INCOMPLETE) return res;
        if (res < 0) {
            break;
        }
        if (res > 0) {
            iter += res;
            request->headers_len++;
        }
    }

    res = parse_string(iter, iter_end - iter, "\r\n");
    if (res < 0) return res;
    iter += res;

    return iter - buf;
}

static int http_server_add(http_server_t *self, http_conn_t *conn) {
    for (size_t i = 0; i < HTTP_CONN_COUNT_MAX; i++) {
        if (self->conn[i] == NULL) {
            self->conn[i] = conn;
            conn->server = self;
            return 0;
        }
    }

    return -1;
}

static int http_server_remove(http_server_t *self, http_conn_t *conn) {
    for (size_t i = 0; i < HTTP_CONN_COUNT_MAX; i++) {
        if (self->conn[i] == conn) {
            self->conn[i] = NULL;
            conn->server = NULL;
            return 0;
        }
    }

    return -1;
}

static void http_conn_close(http_conn_t *self, int epollfd) {
    http_conn_epoll_deregister(self, epollfd);
    http_server_remove(self->server, self);
    http_conn_deinit(self);
    free(self);
}

static int http_conn_read(http_conn_t *self, int epollfd) {
    char buf[4096];
    int nread = read(self->fd, buf, 4096);
    if (nread < 0) {
        if (errno == EAGAIN) {
            return 0;
        }

        error("Failed to read http client fd");
        return -1;
    } else if (nread == 0) {
        http_conn_close(self, epollfd);
    } else {
        http_request_t req = {0};
        int res = parse_request(buf, nread, &req);
        if (res < 0) {
            error("Failed to parse HTTP request: %d.", res);
            http_conn_close(self, epollfd);
            return 0;
        }

        self->server->handle(self, &req);
    }

    return 0;
}

int http_conn_write_header(http_conn_t *self, http_response_t *resp) {
    dprintf(self->fd, "HTTP/1.1 %d %s\r\n", resp->status, http_reason_phrase(resp->status));
    for (size_t i = 0; i < resp->headers_len; i++) {
        dprintf(self->fd, "%s: %s\r\n", resp->headers[i].name, resp->headers[i].value);
    }
    write(self->fd, "\r\n", 2);
    return 0;
}

int http_conn_write_chunk(http_conn_t *self, const uint8_t *chunk, size_t chunk_len) {
    dprintf(self->fd, "%zx\r\n", chunk_len);
    
    int res = write(self->fd, chunk, chunk_len);
    if (res < chunk_len) {
        return -1;
    }

    res = write(self->fd, "\r\n", 2);
    if (res < 2) {
        return -1;
    }

    return 0;
}

int http_conn_write_done(http_conn_t *self) {
    int res = write(self->fd, "0\r\n\r\n", 5);
    if (res < 0) {
        return -1;
    }
    if (res != 5) {
        return -1;
    }

    return 0;
}

int http_response_set_header(http_response_t *self, const char *name, const char *value) {
    if (self->headers_len == HTTP_HEADER_COUNT_MAX) return -1;
    strncpy(self->headers[self->headers_len].name, name, HTTP_HEADER_KEY_LEN_MAX);
    strncpy(self->headers[self->headers_len].value, value, HTTP_HEADER_VAL_LEN_MAX);
    self->headers_len++;

    return 0;
}

int http_conn_init(http_conn_t *self, int fd) {
    memset(self, 0, sizeof(http_conn_t));

    int res = fcntl(fd, F_GETFL, 0);
    if (res < 0) {
        return -1;
    }
    res = fcntl(fd, F_SETFL, res | O_NONBLOCK);
    if (res < 0) {
        return -1;
    }
    self->fd = fd;
    self->read_task = (task_t) {
        .self = self,
        .call = (int (*)(void*, int)) http_conn_read,
    };

    return 0;
}

void http_conn_deinit(http_conn_t *self) {
    close(self->fd);
    self->fd = -1;
}

int http_conn_epoll_register(http_conn_t *self, int epollfd) {
    struct epoll_event event = {0};
    event.events = EPOLLIN;
    event.data.ptr = &self->read_task;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, self->fd, &event) < 0) {
        return -1;
    }

    return 0;
}

int http_conn_epoll_deregister(http_conn_t *self, int epollfd) {
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, self->fd, NULL) == -1) {
        return -1;
    }

    return 0;
}

static int http_server_accept(http_server_t *self, int epollfd) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int res = accept(self->fd, (struct sockaddr *) &addr, &addr_len);
    if (res < 0) {
        error("Failed to accept client connection");
        return -1;
    }

    http_conn_t *conn = calloc(1, sizeof(http_conn_t));
    if (conn == NULL) {
        error("Failed to allocate memory for http_conn_t");
        return -1;
    }

    if (http_conn_init(conn, res) < 0) {
        error("Failed to initialize http_conn_t.");
        goto error0;
    }

    if (http_server_add(self, conn) < 0) {
        error("Failed to add http_conn_t to server.");
        goto error1;
    }

    if (http_conn_epoll_register(conn, epollfd) < 0) {
        error("Failed to register http_conn_t with epoll instance.");
        goto error2;
    }

    return 0;
error2:
    http_server_remove(self, conn);
error1:
    http_conn_deinit(conn);
error0:
    free(conn);
    return -1;
}

int http_server_init(http_server_t *self, uint16_t port, http_handle_func_t handle, void *ctx) {
    memset(self, 0, sizeof(http_server_t));
    self->ctx = ctx;
    self->handle = handle;
    self->accept_task = (task_t) {
        .self = self,
        .call = (int (*)(void*, int)) http_server_accept,
    };
    self->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (self->fd < 0) {
        error("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    if (setsockopt(self->fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        error("Failed to set SO_REUSEADDR on socket: %s", strerror(errno));
        goto error0;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if ((bind(self->fd, (struct sockaddr *) &addr, sizeof(addr))) < 0) {
        error("Failed to bind socket to address: %s", strerror(errno));
        goto error0;
    }

    if ((listen(self->fd, TCP_ACCEPT_QUEUE_DEPTH)) < 0) {
        error("Failed to listen on socket: %s", strerror(errno));
        goto error0;
    }

    return 0;

error0:
    close(self->fd);
    return -1;
}

void http_server_deinit(http_server_t *self) {
    for (size_t i = 0; i < HTTP_CONN_COUNT_MAX; i++) {
        http_conn_t *conn = self->conn[i];
        if (conn) {
            free(conn);
            self->conn[i] = NULL;
        }
    }
}

int http_server_epoll_register(http_server_t *self, int epollfd) {
    struct epoll_event event = {0};
    event.events = EPOLLIN;
    event.data.ptr = &self->accept_task;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, self->fd, &event) < 0) {
        error("Failed to deregister listening socket with epoll instance");
        return -1;
    }

    return 0;
}

int http_server_epoll_deregister(http_server_t *self, int epollfd) {
    for (size_t i = 0; i < HTTP_CONN_COUNT_MAX; i++) {
        http_conn_t *conn = self->conn[i];
        if (conn) {
            if (http_conn_epoll_deregister(conn, epollfd) < 0) {
                error("Failed to deregister http_conn_t with epoll instance");
                return -1;
            }
        }
    }

    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, self->fd, NULL) == -1) {
        error("Failed to deregister listening socket with epoll instance");
        return -1;
    }

    return 0;
}
