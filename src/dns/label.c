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
    cursor_add_bits (&c, 2);
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
dns_label_to_string (const uint8_t *label, char *buf, size_t len, size_t *out)
{
    if (*out >= len) return DNS_ERR_NO_SPACE;

    char *s   = buf + *out;
    char *lim = buf + len - 1;
    for (size_t j = 1; j <= label[0]; j++)
    {
        uint8_t c = label[j];
        if (c < 0x21 || c > 0x7e)
        {
            if (lim - s < (ptrdiff_t)DNS_LABEL_ESCAPE_SIZE) goto no_space;
            *s++ = '\\';
            *s++ = '0' + c / 100;
            *s++ = '0' + c / 10 % 10;
            *s++ = '0' + c % 10;
        }
        else if (strchr (".\\\"();@$", c) != NULL)
        {
            if (lim - s < 2) goto no_space;
            *s++ = '\\';
            *s++ = c;
        }
        else
        {
            if (lim - s < 1) goto no_space;
            *s++ = c;
        }
    }
    *s   = '\0';
    *out = s - buf;
    return DNS_OK;

no_space:
    buf[*out] = '\0';
    return DNS_ERR_NO_SPACE;
}

// p points just past the backslash. Accepts exactly three decimal
// digits with value <= 255 and stores it in *out.
static bool
parse_decimal_escape (const char *p, uint8_t *out)
{
    for (int i = 0; i < 3; i++)
        if (!ascii_isdigit (p[i])) return false;
    unsigned v = (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');
    if (v > 255) return false;
    *out = v;
    return true;
}

dns_error_t
dns_label_from_string (const char **str, uint8_t *label, size_t len)
{
    const char *p = *str;
    size_t      n = 0;

    if (len == 0) return DNS_ERR_NO_SPACE;

    for (; *p != '.' && *p != '\0'; p++)
    {
        uint8_t c = (uint8_t)*p;
        if (c == '\\')
        {
            if (ascii_isdigit (p[1]))
            {
                if (!parse_decimal_escape (p + 1, &c)) return DNS_ERR_BAD_TEXT;
                p += 3;
            }
            else if (p[1] != '\0')
            {
                c = (uint8_t)*++p;
            }
            else
            {
                return DNS_ERR_BAD_TEXT;
            }
        }
        if (1 + n >= len) return DNS_ERR_NO_SPACE;
        label[1 + n++] = c;
    }
    if (n > DNS_LABEL_MAX) return DNS_ERR_LABEL_TOO_LONG;

    label[0] = n;
    *str     = p;
    return DNS_OK;
}
