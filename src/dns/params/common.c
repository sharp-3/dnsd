#include "common.h"
#include "utils/string.h"

bool
params_generic_from_string (const char *str, const char *prefix, uint32_t max, uint32_t *out)
{
    for (; *prefix; prefix++, str++)
        if (ascii_tolower (*str) != ascii_tolower (*prefix)) return false;

    if (*str == '\0') return false;

    uint32_t value = 0;
    for (; *str; str++)
    {
        if (!ascii_isdigit (*str)) return false;
        value = value * 10 + (uint32_t)(*str - '0');
        if (value > max) return false; // also stops before value can overflow
    }
    *out = value;
    return true;
}
