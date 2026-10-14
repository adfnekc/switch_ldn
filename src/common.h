#ifndef SWITCH_LDN_COMMON_H
#define SWITCH_LDN_COMMON_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */

typedef enum {
    LOG_TRACE = 0,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
} LogLevel;

void log_set_level(LogLevel level);
void log_msg(LogLevel level, const char *file, int line, const char *fmt, ...);

#define LOG_T(...) log_msg(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_D(...) log_msg(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_I(...) log_msg(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_W(...) log_msg(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_E(...) log_msg(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* Little helpers                                                     */
/* ------------------------------------------------------------------ */

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define UNUSED(x) ((void)(x))

static inline uint16_t rd_be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static inline void wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static inline uint32_t rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void wr_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

static inline uint64_t rd_be64(const uint8_t *p)
{
    return ((uint64_t)rd_be32(p) << 32) | rd_be32(p + 4);
}

static inline void wr_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)(v >> 8);
}

static inline uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void wr_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static inline void wr_be64(uint8_t *p, uint64_t v)
{
    wr_be32(p, (uint32_t)(v >> 32));
    wr_be32(p + 4, (uint32_t)(v & 0xFFFFFFFFu));
}

static inline uint64_t rd_le64(const uint8_t *p)
{
    return (uint64_t)rd_le32(p) | ((uint64_t)rd_le32(p + 4) << 32);
}

static inline void wr_le64(uint8_t *p, uint64_t v)
{
    wr_le32(p, (uint32_t)(v & 0xFFFFFFFFu));
    wr_le32(p + 4, (uint32_t)(v >> 32));
}

void hex_dump(const char *prefix, const void *data, size_t len);

/* Monotonic milliseconds. */
uint64_t now_ms(void);

#endif /* SWITCH_LDN_COMMON_H */
