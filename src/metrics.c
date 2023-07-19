#define _GNU_SOURCE
#include <metrics.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

const char* metric_type_str(metric_type_t type) {
    switch (type) {
        case METRIC_TYPE_COUNTER: return "counter";
        case METRIC_TYPE_GAUGE: return "gauge";
        case METRIC_TYPE_HISTOGRAM: return "history";
        case METRIC_TYPE_SUMMARY: return "summary";
        default: return "untyped";
    }
}

static int metric_gauge_points(metric_t *metric, metric_point_t *points, size_t count) {
    metric_gauge_t *gauge = (metric_gauge_t*) metric;

    if (count < 1) return -1;

    double value;
    int res = gauge->value(gauge, &value);
    if (res < 0) {
        return -1;
    }

    points[0].value = value;
    for (size_t i = 0; i < gauge->metric.label_count; i++) {
        memcpy(&points[0].labels[i], &gauge->metric.labels[i], sizeof(metric_label_t));
        points[0].label_count++;
    }

    return 1;
}

int metric_gauge_init(metric_gauge_t *gauge, const char *name, metric_label_t *labels, size_t label_count) {
    gauge->metric.name = name;
    gauge->metric.type = METRIC_TYPE_GAUGE;
    for (size_t i = 0; i < label_count; i++) {
        memcpy(&gauge->metric.labels[i], &labels[i], sizeof(metric_label_t));
        gauge->metric.label_count++;
    }
    gauge->metric.points = metric_gauge_points;

    return 0;
}

void metric_gauge_deinit(metric_gauge_t *gauge) {

}

void metric_counter_inc(metric_counter_t *counter) {
    atomic_fetch_add(&counter->count, 1);
}

static int metric_counter_points(metric_t *metric, metric_point_t *points, size_t count) {
    metric_counter_t *counter = (metric_counter_t*) metric;

    atomic_ullong value = atomic_load(&counter->count);

    if (count < 1) return -1;

    points[0].value = (double) value;
    for (size_t i = 0; i < counter->metric.label_count; i++) {
        memcpy(&points[0].labels[i], &counter->metric.labels[i], sizeof(metric_label_t));
        points[0].label_count++;
    }

    return 1;
}

int metric_counter_init(metric_counter_t *counter, const char *name, metric_label_t *labels, size_t label_count) {
    counter->metric.name = name;
    counter->metric.type = METRIC_TYPE_COUNTER;
    counter->metric.points = metric_counter_points;
    for (size_t i = 0; i < label_count; i++) {
        memcpy(&counter->metric.labels[i], &labels[i], sizeof(metric_label_t));
        counter->metric.label_count++;
    }
    counter->count = 0;

    return 0;
}

void metric_counter_deinit(metric_counter_t *counter) {

}

int metric_client_init(metric_client_t *client) {
    memset(client, 0, sizeof(metric_client_t));
    client->fd = STDOUT_FILENO;
    client->buf = calloc(1, sizeof(METRIC_CLIENT_REQUEST_MAX));
    if (client->buf == NULL) {
        return -1;
    }
    
    client->buf_capacity = METRIC_CLIENT_REQUEST_MAX;
    client->buf_len = 0;

    return 0;
}

int metric_client_deinit(metric_client_t *client) {
    free(client->buf);
    return 0;
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

int metric_client_unregister(metric_client_t *client, metric_t *metric) {
    for (size_t i = 0; i < METRIC_CLIENT_METRIC_COUNT_MAX; i++) {
        if (client->metrics[i] == metric) {
            client->metrics[i] = NULL;
            return 0;
        }
    }

    return -1;
}

int metric_client_print(metric_client_t *client) {
    for (size_t i = 0; i < METRIC_CLIENT_METRIC_COUNT_MAX; i++) {
        metric_t *metric = client->metrics[i];
        if (metric == NULL) continue;
        metric_point_t points[1];
        int res = metric->points(metric, points, 1);
        if (res < 0) {
            return -1;
        }
        if (res > 0) {
            for (size_t i = 0; i < res; i++) {
                dprintf(client->fd, "# TYPE %s %s\n", metric->name, metric_type_str(metric->type));
                dprintf(client->fd, "%s", metric->name);
                if (metric->label_count > 0) {
                    dprintf(client->fd, "{");
                    for (size_t j = 0; j < metric->label_count; j++) {
                        if (j != 0) dprintf(client->fd, ",");
                        dprintf(client->fd, "%s=\"%s\"", metric->labels[i].key, metric->labels[i].val);
                    }
                    dprintf(client->fd, "}");
                }
                dprintf(client->fd, " %lg\n\n", points[i].value);
            }
        }
    }

    return 0;
}

int metric_client_poll(metric_client_t *client) {
    int nread = read(client->fd, &client->buf + client->buf_len, client->buf_capacity - client->buf_len);
    if (nread < 0) {
        if (nread == EAGAIN) return 0;
    
        return -1;
    }
}