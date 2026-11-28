#include "common.h"
#include "utils/string.h"

void
params_to_string (const params_table_t *t, uint32_t value, GString *gs)
{
    for (size_t i = 0; i < t->count; i++)
    {
        if (t->names[i].value == value)
        {
            g_string_append (gs, t->names[i].name);
            return;
        }
    }
    g_string_append_printf (gs, "%s%lu", t->prefix, (unsigned long)value);
}

// Parses the generic form of t into *out; see params_from_string.
static bool
generic_from_string (const params_table_t *t, const char *str, uint32_t *out)
{
    for (const char *prefix = t->prefix; *prefix; prefix++, str++)
        if (ascii_tolower (*str) != ascii_tolower (*prefix)) return false;

    if ('\0' == *str) return false;

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
