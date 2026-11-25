#ifndef DNSD_UTILS_STRING_H
#define DNSD_UTILS_STRING_H

#include <stddef.h>
#include <stdint.h>

// ASCII (locale-independent, unlike <ctype.h>)
static inline bool
ascii_isdigit (uint8_t c)
{
    return c >= '0' && c <= '9';
}

static inline bool
ascii_isprint (uint8_t c)
{
    return c >= 0x20 && c <= 0x7e;
}

static inline uint8_t
ascii_tolower (uint8_t c)
{
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

// comparison
bool
str_equal_nocase (const char *a, const char *b);

#endif
