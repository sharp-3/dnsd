#include <stdio.h>

#include "common.h"
#include "utils/string.h"

const char *
params_display_r (const params_table_t *t, uint32_t value, char *buf, size_t len)
{
    for (size_t i = 0; i < t->count; i++)
        if (t->names[i].value == value) return t->names[i].name;
    snprintf (buf, len, "%s%lu", t->prefix, (unsigned long)value);
    return buf;
}

// Parses the generic form of t into *out; see params_from_string.
static bool
generic_from_string (const params_table_t *t, const char *str, uint32_t *out)
{
    for (const char *prefix = t->prefix; *prefix; prefix++, str++)
        if (ascii_tolower (*str) != ascii_tolower (*prefix)) return false;

    if (*str == '\0') return false;

    uint32_t value = 0;
    for (; *str; str++)
    {
        if (!ascii_isdigit (*str)) return false;
        uint32_t digit = (uint32_t)(*str - '0');
        // value * 10 + digit > max, checked without overflow
        if (t->max < digit || (t->max - digit) / 10 < value) return false;
        value = value * 10 + digit;
    }
    *out = value;
    return true;
}

bool
params_from_string (const params_table_t *t, const char *str, uint32_t *out)
{
    for (size_t i = 0; i < t->count; i++)
    {
        if (str_equal_nocase (str, t->names[i].name))
        {
            *out = t->names[i].value;
            return true;
        }
    }
    return generic_from_string (t, str, out);
}
