#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>

#define METRICS_MAX_LABEL_COUNT 16
#define METRICS_MAX_LABEL_KEY_SIZE 64
#define METRICS_MAX_LABEL_VAL_SIZE 32

typedef struct metric_label {
    char key[METRICS_MAX_LABEL_KEY_SIZE];
    char val[METRICS_MAX_LABEL_VAL_SIZE];
} metric_label_t;

typedef struct metric_point {
    metric_label_t labels[METRICS_MAX_LABEL_COUNT];
    size_t label_count;
    double value;
    uint64_t timestamp;
} metric_point_t;

typedef enum metric_type {
    METRIC_TYPE_UNTYPED = 0,
    METRIC_TYPE_COUNTER,
    METRIC_TYPE_GAUGE,
    METRIC_TYPE_HISTOGRAM,
    METRIC_TYPE_SUMMARY,
} metric_type_t;

const char* metric_type_str(metric_type_t type);


typedef struct metric {
    const char *name;
    metric_type_t type;
    metric_label_t labels[METRICS_MAX_LABEL_COUNT];
    size_t label_count;
    /**
     * Fill the given array with points describing the current metric value. Return
     * the number of elements
     * \param self: the metric.
     * \param points: an array of points.
     * \param count: the capacity of points.
     * \return the number of points initialized on success or -1 on error.
     */
    int (*points)(struct metric*, metric_point_t *points, size_t count);
} metric_t;

typedef struct metric_gauge {
    metric_t metric;
    int (*value)(struct metric_gauge *gauge, double *res);
} metric_gauge_t;

int metric_gauge_init(metric_gauge_t *gauge, const char *name, metric_label_t *labels, size_t label_count);
void metric_gauge_deinit(metric_gauge_t *counter);

typedef struct metric_counter {
    metric_t metric;
    atomic_ullong count;
} metric_counter_t;

int metric_counter_init(metric_counter_t *counter, const char *name, metric_label_t *labels, size_t label_count);
void metric_counter_deinit(metric_counter_t *counter);
void metric_counter_inc(metric_counter_t *counter);

#define METRIC_CLIENT_METRIC_COUNT_MAX 1024
#define METRIC_CLIENT_REQUEST_MAX 16384
typedef struct metric_client {
    int fd;
    metric_t *metrics[METRIC_CLIENT_METRIC_COUNT_MAX];
    uint8_t *buf;
    size_t buf_capacity;
    size_t buf_len;
} metric_client_t;

int metric_client_init(metric_client_t *client);
int metric_client_deinit(metric_client_t *client);
int metric_client_register(metric_client_t *client, metric_t *metric);
int metric_client_unregister(metric_client_t *client, metric_t *metric);
int metric_client_print(metric_client_t *client);

#endif
