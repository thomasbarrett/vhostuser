#define _GNU_SOURCE
#include <metrics.h>
#include <log.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

const char* metric_type_str(metric_type_t type) {
    switch (type) {
        case METRIC_TYPE_COUNTER: return "counter";
        case METRIC_TYPE_GAUGE: return "gauge";
        case METRIC_TYPE_HISTOGRAM: return "histogram";
        case METRIC_TYPE_SUMMARY: return "summary";
        default: return "untyped";
    }
}

static int metric_gauge_points(metric_t *metric, metric_point_t *points, size_t count) {
    metric_gauge_t *gauge = (metric_gauge_t*) metric;
    if (count < 1) return -1;
    memset(points, 0, sizeof(metric_point_t));
    if (gauge->value(gauge, &points[0].value) < 0) {
        return -1;
    }
    for (size_t i = 0; i < gauge->metric.label_count; i++) {
        memcpy(&points[0].labels[i], &gauge->metric.labels[i], sizeof(metric_label_t));
        points[0].label_count++;
    }

    return 1;
}

int metric_gauge_init(metric_gauge_t *gauge, const char *name, metric_label_t *labels, size_t label_count, gauge_value_func_t value) {
    memset(gauge, 0, sizeof(metric_gauge_t));
    gauge->metric.name = name;
    gauge->metric.type = METRIC_TYPE_GAUGE;
    gauge->metric.points = metric_gauge_points;
    gauge->value = value;
    if (label_count > METRICS_MAX_LABEL_COUNT) {
        return -1;
    }
    for (size_t i = 0; i < label_count; i++) {
        memcpy(&gauge->metric.labels[i], &labels[i], sizeof(metric_label_t));
        gauge->metric.label_count++;
    }

    return 0;
}

void metric_gauge_deinit(metric_gauge_t *gauge) {}

static int metric_counter_points(metric_t *metric, metric_point_t *points, size_t count) {
    metric_counter_t *counter = (metric_counter_t*) metric;

    if (count < 1) return -1;
    memset(points, 0, sizeof(metric_point_t));
    points[0].value = (double) atomic_load(&counter->count);
    for (size_t i = 0; i < counter->metric.label_count; i++) {
        memcpy(&points[0].labels[i], &counter->metric.labels[i], sizeof(metric_label_t));
        points[0].label_count++;
    }

    return 1;
}

int metric_counter_init(metric_counter_t *counter, const char *name, metric_label_t *labels, size_t label_count) {
    memset(counter, 0, sizeof(metric_counter_t));
    counter->metric.name = name;
    counter->metric.type = METRIC_TYPE_COUNTER;
    counter->metric.points = metric_counter_points;
    if (label_count > METRICS_MAX_LABEL_COUNT) {
        return -1;
    }
    for (size_t i = 0; i < label_count; i++) {
        memcpy(&counter->metric.labels[i], &labels[i], sizeof(metric_label_t));
        counter->metric.label_count++;
    }

    return 0;
}

void metric_counter_deinit(metric_counter_t *counter) {}

void metric_counter_inc(metric_counter_t *counter, uint64_t count) {
    atomic_fetch_add(&counter->count, count);
}

static int metric_write(metric_t *metric, uint8_t *buf, size_t buf_len) {
    metric_point_t points[1];

    int res1 = metric->points(metric, points, 1);
    if (res1 < 0) {
        return -1;
    }

    char *iter = (char*) buf;
    char *iter_end = (char*) buf + buf_len;
    if (res1 > 0) {
        for (size_t i = 0; i < res1; i++) {
            int res2 = snprintf(iter, iter_end - iter, "# TYPE %s %s\n", metric->name, metric_type_str(metric->type));
            if (res2 < 0 || res2 > iter_end - iter) {
                return -1;
            }
            iter += res2;

            res2 = snprintf(iter, iter_end - iter, "%s", metric->name);
            if (res2 < 0 || res2 > iter_end - iter) {
                return -1;
            }
            iter += res2;

            if (metric->label_count > 0) {
                res2 = snprintf(iter, iter_end - iter, "{");
                if (res2 < 0 || res2 > iter_end - iter) {
                    return -1;
                }
                iter += res2;
                for (size_t j = 0; j < metric->label_count; j++) {
                    if (j != 0) {
                        res2 = snprintf(iter, iter_end - iter, ",");
                        if (res2 < 0 || res2 > iter_end - iter) {
                            return -1;
                        }
                        iter += res2;
                    }
                    res2 = snprintf(iter, iter_end - iter, "%s=\"%s\"", metric->labels[i].key, metric->labels[i].val);
                    if (res2 < 0 || res2 > iter_end - iter) {
                        return -1;
                    }
                    iter += res2;
                }
                res2 = snprintf(iter, iter_end - iter, "}");
                    if (res2 < 0 || res2 > iter_end - iter) {
                    return -1;
                }
                iter += res2;
            }
            res2 = snprintf(iter, iter_end - iter, " %.15lg\n\n", points[i].value);
            if (res2 < 0 || res2 > iter_end - iter) {
                return -1;
            }
            iter += res2;
        }
    }

    return iter - (char*) buf;
}

static void metric_client_http_handle(http_conn_t *conn, http_request_t *req) {
    http_response_t resp = {0};
    resp.status = 200;
    http_response_set_header(&resp, "Content-Type", "text/plain; version=0.0.4");
    http_response_set_header(&resp, "Transfer-Encoding", "chunked");
    http_conn_write_header(conn, &resp);

    metric_client_t *client = conn->server->ctx;
    for (size_t i = 0; i < METRIC_CLIENT_METRIC_COUNT_MAX; i++) {
        metric_t *metric = client->metrics[i];
        if (metric) {
            uint8_t buf[4096];
            int res = metric_write(metric, buf, 4096);
            if (res < 0) {
                error("Failed to write metric.");
            }
            if (http_conn_write_chunk(conn, buf, res) < 0) {
                error("Failed to write chunk.");
            }
        }
    }
    http_conn_write_done(conn);
}

int metric_client_init(metric_client_t *client, uint16_t port) {
    memset(client, 0, sizeof(metric_client_t));
    if (http_server_init(&client->http_server, port, metric_client_http_handle, client) < 0) {
        return -1;
    }

    return 0;
}

void metric_client_deinit(metric_client_t *client) {
    http_server_deinit(&client->http_server);
}

int metric_client_register(metric_client_t *client, metric_t *metric) {
    for (size_t i = 0; i < METRIC_CLIENT_METRIC_COUNT_MAX; i++) {
        if (client->metrics[i] == NULL) {
            client->metrics[i] = metric;
            return 0;
        }
    }

    return -1;
}

int metric_client_deregister(metric_client_t *client, metric_t *metric) {
    for (size_t i = 0; i < METRIC_CLIENT_METRIC_COUNT_MAX; i++) {
        if (client->metrics[i] == metric) {
            client->metrics[i] = NULL;
            return 0;
        }
    }

    return -1;
}

int metric_client_epoll_register(metric_client_t *self, int epollfd) {
    return http_server_epoll_register(&self->http_server, epollfd);
}

int metric_client_epoll_deregister(metric_client_t *self, int epollfd) {
    return http_server_epoll_deregister(&self->http_server, epollfd);
}
