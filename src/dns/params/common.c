#include <string.h>

#include "common.h"

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

static bool
generic_from_string (const params_table_t *t, const char *str, uint32_t *out)
{
    size_t prefix_len = strlen (t->prefix);
    if (0 != g_ascii_strncasecmp (str, t->prefix, prefix_len)) return false;

    guint64 value;
    if (!g_ascii_string_to_unsigned (str + prefix_len, 10, 0, t->max, &value, NULL)) return false;
    *out = (uint32_t)value;
    return true;
}

bool
params_from_string (const params_table_t *t, const char *str, uint32_t *out)
{
    for (size_t i = 0; i < t->count; i++)
    {
        if (0 == g_ascii_strcasecmp (str, t->names[i].name))
        {
            *out = t->names[i].value;
            return true;
        }
    }
    return generic_from_string (t, str, out);
}
