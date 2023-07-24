#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <http.h>

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

struct metric_gauge;

typedef int (*gauge_value_func_t)(struct metric_gauge *gauge, double *res);

typedef struct metric_gauge {
    metric_t metric;
    gauge_value_func_t value;
} metric_gauge_t;

/**
 * Initialize the metric_gauge_t with the given name, labels, and value function.
 * 
 * \param gauge: the gauge.
 * \param name: the metric name.
 * \param labels: the metric labels.
 * \param label_count: the number of metric labels.
 * \param value: the gauge value function.
 * \return 0 on success and -1 on error.
 */
int metric_gauge_init(metric_gauge_t *gauge, const char *name, metric_label_t *labels, size_t label_count, gauge_value_func_t value);

/**
 * Deinitialize the metric_gauge_t.
 * 
 * \param gauge: the gauge.
 */
void metric_gauge_deinit(metric_gauge_t *gauge);

typedef struct metric_counter {
    metric_t metric;
    atomic_ullong count;
} metric_counter_t;

/**
 * Initialize the metric_counter_t with the given name, labels, and value function.
 * 
 * \param counter: the counter.
 * \param name: the metric name.
 * \param labels: the metric labels.
 * \param label_count: the number of metric labels.
 * \return 0 on success and -1 on error.
 */
int metric_counter_init(metric_counter_t *counter, const char *name, metric_label_t *labels, size_t label_count);

/**
 * Deinitialize the metric_counter_t.
 * 
 * \param counter: the counter.
 */
void metric_counter_deinit(metric_counter_t *counter);

/**
 * Increment the metric_count_t by count. This function is safe to call from any thread.
 * 
 * \param counter: the counter.
 * \param count: the amount to increment the counter by. 
 */
void metric_counter_inc(metric_counter_t *counter, uint64_t count);

#define METRIC_CLIENT_METRIC_COUNT_MAX 1024
typedef struct metric_client {
    http_server_t http_server;
    metric_t *metrics[METRIC_CLIENT_METRIC_COUNT_MAX];
} metric_client_t;

int metric_client_init(metric_client_t *client, uint16_t port);
void metric_client_deinit(metric_client_t *client);
int metric_client_epoll_register(metric_client_t *self, int epollfd);
int metric_client_epoll_deregister(metric_client_t *self, int epollfd);
int metric_client_register(metric_client_t *client, metric_t *metric);
int metric_client_deregister(metric_client_t *client, metric_t *metric);

#endif
