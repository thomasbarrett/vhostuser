#ifndef HTTP_H
#define HTTP_H

#include <task_queue.h>
#include <stdint.h>
#include <stddef.h>

#define HTTP_CONN_COUNT_MAX 16

#define HTTP_HEADER_KEY_LEN_MAX 63
#define HTTP_HEADER_VAL_LEN_MAX 1023
#define HTTP_HEADER_COUNT_MAX 32

typedef struct http_header {
    char name[HTTP_HEADER_KEY_LEN_MAX + 1];
    char value[HTTP_HEADER_VAL_LEN_MAX + 1];
} http_header_t;

#define HTTP_REQUEST_METHOD_LEN 7
#define HTTP_REQUEST_URI_LEN 511
#define HTTP_REQUEST_VERSION_LEN 15

typedef struct http_request {
    char method[HTTP_REQUEST_METHOD_LEN + 1];
    char uri[HTTP_REQUEST_URI_LEN + 1];
    char version[HTTP_REQUEST_VERSION_LEN + 1];
    http_header_t headers[HTTP_HEADER_COUNT_MAX];
    size_t headers_len;
} http_request_t;

typedef struct http_response {
    int status;
    http_header_t headers[HTTP_HEADER_COUNT_MAX];
    size_t headers_len;
} http_response_t;

int http_response_set_header(http_response_t *self, const char *name, const char *value);

struct http_server;

typedef struct http_conn {
    struct http_server *server;
    int fd;
    task_t read_task;
} http_conn_t;

/**
 * Initialize the http_conn_t; 
 * 
 * \param self: the conn.
 */
int http_conn_init(http_conn_t *self, int fd);

/**
 * Deinitialize the http_conn_t; 
 * 
 * \param self: the conn.
 */
void http_conn_deinit(http_conn_t *self);

/**
 * Register the http_conn_t with the specified epoll instance.
 * 
 * \param self: the conn.
 * \param epollfd: the epoll instance.
 * \return 0 on success and -1 on error.
 */
int http_conn_epoll_register(http_conn_t *self, int epollfd);

/**
 * Deregister the http_conn_t with the specified epoll instance.
 * 
 * \param self: the conn.
 * \param epollfd: the epoll instance.
 * \return 0 on success and -1 on error.
 */
int http_conn_epoll_deregister(http_conn_t *self, int epollfd);

/**
 * Write the http_response_t on the given http_conn_t.
 * 
 * \param self: the conn.
 * \param resp: the http response.
 * \param body: the http body.
 * \param body_len: the http body length.
 */
int http_conn_write_header(http_conn_t *self, http_response_t *resp);
int http_conn_write_chunk(http_conn_t *self, const uint8_t *chunk, size_t chunk_len);
int http_conn_write_done(http_conn_t *self);

typedef void (*http_handle_func_t)(http_conn_t *conn, http_request_t *req);

typedef struct http_server {
    int fd;
    task_t accept_task;
    http_conn_t *conn[HTTP_CONN_COUNT_MAX];
    http_handle_func_t handle;
    void *ctx;
} http_server_t;

/**
 * Initialize the http_server_t; 
 * 
 * \param self: the server.
 */
int http_server_init(http_server_t *self, uint16_t port, http_handle_func_t handle, void *ctx);

/**
 * Deinitialize the http_server_t; 
 * 
 * \param self: the server.
 */
void http_server_deinit(http_server_t *self);

/**
 * Register the http_server_t with the specified epoll instance.
 * 
 * \param self: the server.
 * \param epollfd: the epoll instance.
 * \return 0 on success and -1 on error.
 */
int http_server_epoll_register(http_server_t *self, int epollfd);

/**
 * Deregister the http_server_t with the specified epoll instance.
 * 
 * \param self: the server.
 * \param epollfd: the epoll instance.
 * \return 0 on success and -1 on error.
 */
int http_server_epoll_deregister(http_server_t *self, int epollfd);

#endif
