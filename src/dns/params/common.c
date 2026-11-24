#include "common.h"

static inline char
ascii_tolower (char c)
{
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

bool
params_equal (const char *a, const char *b)
{
    for (; *a && *b; a++, b++)
        if (ascii_tolower (*a) != ascii_tolower (*b)) return false;
    return *a == *b;
}

bool
params_generic_from_string (const char *str, const char *prefix, uint32_t max, uint32_t *out)
{
    for (; *prefix; prefix++, str++)
        if (ascii_tolower (*str) != ascii_tolower (*prefix)) return false;

    if (*str == '\0') return false;

    uint32_t value = 0;
    for (; *str; str++)
    {
        if (*str < '0' || *str > '9') return false;
        value = value * 10 + (uint32_t)(*str - '0');
        if (value > max) return false; // also stops before value can overflow
    }
    *out = value;
    return true;
}
