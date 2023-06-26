#ifndef LOG_H
#define LOG_H

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO  1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_PANIC 4

#define debug(...) print_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define info(...) print_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define warn(...) print_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define error(...) print_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define panic(...) print_log(LOG_LEVEL_PANIC, __FILE__, __LINE__, __VA_ARGS__)

void print_log(int level, char *file, int line, char *fmt, ...);

#endif
