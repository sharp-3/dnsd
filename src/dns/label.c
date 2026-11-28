#include <string.h>

#include "dns/label.h"
#include "packet/cursor.h"
#include "utils/string.h"

// A cursor over the first octets of label, for reading only (hence the cast).
static cursor_t
label_cursor (const uint8_t *label, size_t len)
{
    cursor_t c;
    cursor_init (&c, (uint8_t *)label, len);
    return c;
}

dns_label_type_t
dns_label_type (const uint8_t *label)
{
    cursor_t c = label_cursor (label, 1);
    return read_bits (&c, 2);
}

size_t
dns_label_size (const uint8_t *label)
{
    switch (dns_label_type (label))
    {
    case DNS_LABEL_TYPE_NORMAL:
        return 1 + (size_t)label[0];
    case DNS_LABEL_TYPE_POINTER:
        return DNS_LABEL_POINTER_SIZE;
    default:
        return 0;
    }
}

size_t
dns_label_pointer_target (const uint8_t *label)
{
    cursor_t c = label_cursor (label, DNS_LABEL_POINTER_SIZE);
    cursor_add (&c, 0, 2);
    return read_bits (&c, 14);
}

void
dns_label_pointer_write (uint8_t *ptr, size_t target)
{
    cursor_t c;
    cursor_init (&c, ptr, DNS_LABEL_POINTER_SIZE);
    emit_bits (&c, 2, DNS_LABEL_TYPE_POINTER);
    emit_bits (&c, 14, target);
}

bool
dns_label_equal (const uint8_t *a, const uint8_t *b)
{
    if (a[0] != b[0]) return false;
    for (size_t i = 1; i <= a[0]; i++)
        if (ascii_tolower (a[i]) != ascii_tolower (b[i])) return false;
    return true;
}

dns_error_t
dns_label_to_string (const uint8_t *self, GString *gs)
{
    for (size_t j = 1; j <= self[0]; j++)
    {
        uint8_t c = self[j];
        if (c < 0x21 || 0x7e < c) g_string_append_printf (gs, "\\%03u", c);
        else if (NULL != strchr (".\\\"();@$", c)) g_string_append_printf (gs, "\\%c", c);
        else g_string_append_c (gs, c);
    }
    return DNS_OK;
}

// p points just past the backslash. Accepts exactly three decimal
// digits with value <= 255 and stores it in *out.
static bool
parse_decimal_escape (const char *p, uint8_t *out)
{
    for (int i = 0; i < 3; i++)
        if (!ascii_isdigit (p[i])) return false;
    unsigned v = (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
    if (255 < v) return false;
    *out = v;
    return true;
}

dns_error_t
dns_label_from_string (uint8_t *self, const char **str)
{
    uint8_t     label[1 + DNS_LABEL_MAX];
    const char *p = *str;
    size_t      n = 0;

    for (; '.' != *p && '\0' != *p; p++)
    {
        uint8_t c = (uint8_t)*p;
        if ('\\' == c)
        {
            if (ascii_isdigit (p[1]))
            {
                if (!parse_decimal_escape (p + 1, &c)) return DNS_ERR_BAD_TEXT;
                p += 3;
            }
            else if ('\0' != p[1])
            {
                c = (uint8_t)*++p;
            }
            else
            {
                return DNS_ERR_BAD_TEXT;
            }
        }
        if (DNS_LABEL_MAX <= n) return DNS_ERR_NAME_LABEL_TOO_LONG;
        label[1 + n++] = c;
    }

    label[0] = n;
    memcpy (self, label, 1 + n);
    *str = p;
    return DNS_OK;
}

void
dns_label_iter_init (dns_label_iter_t *it, const uint8_t *buf, size_t len, size_t pos)
{
    *it = (dns_label_iter_t){.buf = buf, .len = len, .pos = pos};
}

bool
dns_label_iter_next (dns_label_iter_t *it)
{
    if (it->end || DNS_OK != it->err) return false;
    if (it->len <= it->pos)
    {
        it->err = DNS_ERR_NAME_TRUNCATED;
        return false;
    }

    const uint8_t *label = it->buf + it->pos;
    switch (dns_label_type (label))
    {
    case DNS_LABEL_TYPE_NORMAL:
        it->end = 0 == label[0];
        break;
    case DNS_LABEL_TYPE_POINTER:
        it->end = true;
        break;
    default:
        it->err = DNS_ERR_NAME_RESERVED_LABEL;
        return false;
    }
    if (it->len - it->pos < dns_label_size (label))
    {
        it->end = false;
        it->err = DNS_ERR_NAME_TRUNCATED;
        return false;
    }

    it->label = label;
    it->off   = it->pos;
    it->pos += dns_label_size (label);
    return true;
}
