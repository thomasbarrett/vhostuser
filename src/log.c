#include <log.h>

#include <time.h>
#include <stdio.h>
#include <stdarg.h>

static const char* log_level_str(int level) {
    switch (level) {
    case LOG_LEVEL_DEBUG: return "DEBUG";
    case LOG_LEVEL_INFO: return "INFO";
    case LOG_LEVEL_WARN: return "WARN";
    case LOG_LEVEL_ERROR: return "ERROR";
    case LOG_LEVEL_PANIC: return "PANIC";
    default: return "UNKNOWN";
    }
}

void print_log(int level, char *file, int line, char *fmt, ...) {
    time_t now;
    time(&now);
    struct tm *local = gmtime(&now);
    int h = local->tm_hour;
    int m = local->tm_min;
    int s = local->tm_sec;
    printf("[ %s ] %02d:%02d:%02d %s:%d ", log_level_str(level), h, m, s, file, line);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    printf("\n");
}
