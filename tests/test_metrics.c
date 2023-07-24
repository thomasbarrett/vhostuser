#include <src/metrics.c>
#include <src/log.c>

#include <string.h>
#include <assert.h>

#define EXPECTED_HTTP_PORT 8888
#define EXPECTED_EPOLLFD 4

int http_server_init_called = 0;
int http_server_init(http_server_t *self, uint16_t port, http_handle_func_t handle, void *ctx) {
    assert(port == EXPECTED_HTTP_PORT);
    self->handle = handle;
    http_server_init_called++;
    return 0;
}

int http_server_deinit_called = 0;
void http_server_deinit(http_server_t *self) {
    http_server_deinit_called++;
    return;
}

int http_server_epoll_register_called = 0;
int http_server_epoll_register(http_server_t *self, int epollfd) {
    http_server_epoll_register_called++;
    assert(epollfd == EXPECTED_EPOLLFD);
    return 0;
}

int http_server_epoll_deregister_called = 0;
int http_server_epoll_deregister(http_server_t *self, int epollfd) {
    http_server_epoll_deregister_called++;
    assert(epollfd == EXPECTED_EPOLLFD);
    return 0;
}

int http_response_set_header(http_response_t *self, const char *name, const char *value) {
    return 0;
}

int http_conn_write_header(http_conn_t *self, http_response_t *resp) {
    return 0;
}

int http_conn_write_chunk(http_conn_t *self, const uint8_t *chunk, size_t chunk_len) {
    return 0;
}

int http_conn_write_done(http_conn_t *self) {
    return 0;
}

void test_metric_type_str(void) {
    assert(strcmp(metric_type_str(METRIC_TYPE_COUNTER), "counter") == 0);
    assert(strcmp(metric_type_str(METRIC_TYPE_GAUGE), "gauge") == 0);
    assert(strcmp(metric_type_str(METRIC_TYPE_HISTOGRAM), "histogram") == 0);
    assert(strcmp(metric_type_str(METRIC_TYPE_SUMMARY), "summary") == 0);
    assert(strcmp(metric_type_str(METRIC_TYPE_UNTYPED), "untyped") == 0);
}

void test_metric_counter(void) {
    metric_counter_t counter = {0};
    metric_label_t label = {
        .key = {'a'},
        .val = {'b'}
    };
    assert(metric_counter_init(&counter, "test", &label, 1) == 0);
    assert(counter.metric.type == METRIC_TYPE_COUNTER);
    assert(strcmp(counter.metric.name, "test") == 0);
    assert(counter.metric.label_count == 1);
    assert(strcmp(counter.metric.labels[0].key, "a") == 0);
    assert(strcmp(counter.metric.labels[0].val, "b") == 0);

    metric_point_t points[1];
    assert(counter.metric.points(&counter.metric, points, 1) == 1);
    assert(points[0].value == 0);
    assert(points[0].label_count == 1);
    assert(strcmp(points[0].labels[0].key, "a") == 0);
    assert(strcmp(points[0].labels[0].val, "b") == 0);

    metric_counter_inc(&counter, 5);
    assert(counter.metric.points(&counter.metric, points, 1) == 1);
    assert(points[0].value == 5);
    assert(points[0].label_count == 1);
    assert(strcmp(points[0].labels[0].key, "a") == 0);
    assert(strcmp(points[0].labels[0].val, "b") == 0);
}

int gauge_value_func(struct metric_gauge *gauge, double *res) {
    *res = 4.2;
    return 0;
}

void test_metric_gauge(void) {
    metric_gauge_t gauge = {0};
    metric_label_t label = {
        .key = {'a'},
        .val = {'b'}
    };
    assert(metric_gauge_init(&gauge, "test", &label, 1, gauge_value_func) == 0);
    assert(gauge.metric.type == METRIC_TYPE_GAUGE);
    assert(strcmp(gauge.metric.name, "test") == 0);
    assert(gauge.metric.label_count == 1);
    assert(strcmp(gauge.metric.labels[0].key, "a") == 0);
    assert(strcmp(gauge.metric.labels[0].val, "b") == 0);

    metric_point_t points[1];
    assert(gauge.metric.points(&gauge.metric, points, 1) == 1);
    assert(points[0].value == 4.2);
    assert(points[0].label_count == 1);
    assert(strcmp(points[0].labels[0].key, "a") == 0);
    assert(strcmp(points[0].labels[0].val, "b") == 0);
}

void test_metric_client(void) {
    metric_client_t client = {0};
    assert(metric_client_init(&client, EXPECTED_HTTP_PORT) == 0);
    assert(http_server_init_called == 1);
    assert(metric_client_epoll_register(&client, EXPECTED_EPOLLFD) == 0);
    assert(http_server_epoll_register_called == 1);
    assert(metric_client_epoll_deregister(&client, EXPECTED_EPOLLFD) == 0);
    assert(http_server_epoll_deregister_called == 1);
    metric_client_deinit(&client);
    assert(http_server_deinit_called == 1);
}

int main(void) {
    test_metric_type_str();
    test_metric_counter();
    test_metric_gauge();
    test_metric_client();
}
