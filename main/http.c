#include <http.h>
#include <log.h>

#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/epoll.h>

#define HTTP_PORT 8888

static volatile int done = 0;

void handle_sigint(int signal) {
    done = 1;
}

void handle_request(http_conn_t *conn, http_request_t *req) {
    http_response_t resp = {0};
    resp.status = 200;
    http_response_set_header(&resp, "Content-Type", "text/plain; version=0.0.4");
    http_response_set_header(&resp, "Transfer-Encoding", "chunked");
    http_conn_write_header(conn, &resp);
    http_conn_write_chunk(conn, (const uint8_t *) "hello", 5);
    http_conn_write_done(conn);
}

int main(void) {
    signal(SIGINT, handle_sigint);

    int epollfd = epoll_create1(0);
    if (epollfd < 0) {
        return -1;
    }

    http_server_t server;
    if (http_server_init(&server, HTTP_PORT, handle_request, NULL) < 0) {
        error("Failed to initialize http server.");
        return -1;
    }

    if (http_server_epoll_register(&server, epollfd) < 0) {
        error("Failed to register http server with epoll instance.");
        return -1;
    }

    info("Listening on port %d.", HTTP_PORT);

    const size_t EPOLL_MAX_EVENTS = 16;
    int EPOLL_TIMEOUT_MS = 500;
    struct epoll_event events[EPOLL_MAX_EVENTS];
    while (!done) {
        int res = epoll_wait(epollfd, events, EPOLL_MAX_EVENTS, EPOLL_TIMEOUT_MS);
        if (res < 0) {
            /* Exit the loop cleanly upon receiving SIGINT */
            if (errno == EINTR) continue;

            return -1;
        }

        for (size_t i = 0; i < res; i++) {
            task_t *ctx = (task_t*) events[i].data.ptr;
            if (ctx->call(ctx->self, epollfd) < 0) {
                return -1;
            }
        }
    }

    http_server_epoll_deregister(&server, epollfd);
    http_server_deinit(&server);

    close(epollfd);

    info("Exiting.");

    return 0;
}
