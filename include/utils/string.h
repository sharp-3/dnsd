#ifndef DNSD_UTILS_STRING_H
#define DNSD_UTILS_STRING_H

#include <stddef.h>
#include <stdint.h>

// Locale-independent ASCII helpers (<ctype.h> depends on the locale and is undefined for
// negative char values).
static inline bool
ascii_isdigit (uint8_t c)
{
    return c >= '0' && c <= '9';
}

// Printable ASCII, space included (0x20-0x7E).
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

// Whether a and b are equal ignoring ASCII case.
bool
str_equal_nocase (const char *a, const char *b);

#endif
