#include "common.h"

#include <errno.h>
#include <time.h>
#include <unistd.h>

static LogLevel g_level = LOG_INFO;

void log_set_level(LogLevel level)
{
    g_level = level;
}

void log_msg(LogLevel level, const char *file, int line, const char *fmt, ...)
{
    static const char *names[] = {"TRACE", "DEBUG", "INFO ", "WARN ", "ERROR"};

    if (level < g_level) {
        return;
    }

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t ms = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;

    fprintf(stderr, "[%10llu.%03llu] %s %s:%d: ",
            (unsigned long long)(ms / 1000), (unsigned long long)(ms % 1000),
            names[level], file, line);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void hex_dump(const char *prefix, const void *data, size_t len)
{
    const uint8_t *p = data;
    fputs(prefix, stderr);
    for (size_t i = 0; i < len; i++) {
        fputc("0123456789abcdef"[p[i] >> 4], stderr);
        fputc("0123456789abcdef"[p[i] & 0xF], stderr);
    }
    fputc('\n', stderr);
}

uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
