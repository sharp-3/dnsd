#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dns/label.h"
#include "dns/name.h"

// Checks the compression pointer at label, which has avail octets left: it must be whole and
// go back before offset bound to a recorded label start. Stores its target in *target.
static dns_error_t
check_pointer (
    const dns_parser_t *p, const uint8_t *label, size_t avail, size_t bound, size_t *target)
{
    if (avail < DNS_LABEL_POINTER_SIZE) return DNS_ERR_TRUNCATED;
    *target = dns_label_pointer_target (label);
    if (*target >= bound || !dns_parser_test_label (p, *target)) return DNS_ERR_BAD_POINTER;
    return DNS_OK;
}

dns_error_t
dns_name_from_bytes (dns_parser_t *p, dns_name_t *out)
{
    size_t      len;
    dns_error_t err = dns_name_length (p, &len);
    if (!dns_is_ok (err)) return err;

    const uint8_t *ptr   = cursor_ptr (&p->cur);
    size_t         start = cursor_bytes (&p->cur);
    dns_parser_clear_labels (p, start);
    for (size_t i = 0; i < len; i += dns_label_size (ptr + i))
        dns_parser_mark_label (p, start + i);
    cursor_add_bytes (&p->cur, len);

    out->ptr = ptr;
    out->len = len;
    return err;
}

dns_error_t
dns_name_length (const dns_parser_t *p, size_t *size)
{
    assert (cursor_is_aligned (&p->cur));

    const uint8_t *pkt     = p->cur.buf;
    size_t         pkt_len = p->cur.len;
    size_t         start   = cursor_bytes (&p->cur);
    size_t         pos     = start;

    if (cursor_is_overflow (&p->cur)) return DNS_ERR_TRUNCATED;

    for (;;)
    {
        if (pos >= pkt_len) return DNS_ERR_TRUNCATED;

        const uint8_t *label = pkt + pos;
        switch (dns_label_type (label))
        {
        case DNS_LABEL_TYPE_NORMAL:
            if (pkt_len - pos < dns_label_size (label)) return DNS_ERR_TRUNCATED;
            pos += dns_label_size (label);
            if (label[0] == 0) goto done;
            break;
        case DNS_LABEL_TYPE_POINTER:
        {
            size_t      target;
            dns_error_t err = check_pointer (p, label, pkt_len - pos, start, &target);
            if (err != DNS_OK) return err;
            pos += DNS_LABEL_POINTER_SIZE;
            goto done;
        }
        default:
            return DNS_ERR_RESERVED_LABEL;
        }
    }

done:
    *size = pos - start;
    return *size > DNS_NAME_MAX ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

dns_error_t
dns_name_from_string (const char *str, dns_name_t **out)
{
    *out = NULL;

    const char *s = strcmp (str, ".") == 0 ? str + 1 : str;

    // each text octet yields at most one wire octet; +2 for the first length octet and the root
    size_t      size = strlen (s) + 2;
    dns_name_t *name = malloc (sizeof *name + size);
    if (!name) return DNS_ERR_NOMEM;

    uint8_t    *data = (uint8_t *)(name + 1);
    dns_error_t err  = DNS_OK;
    size_t      len  = 0;

    while (*s != '\0')
    {
        err = dns_label_from_string (&s, data + len, size - len);
        if (err != DNS_OK) goto error;
        if (data[len] == 0)
        {
            err = DNS_ERR_BAD_TEXT;
            goto error;
        }
        len += dns_label_size (data + len);
        if (*s == '.') s++;
    }
    data[len++] = 0;

    name->ptr = data;
    name->len = len;
    *out      = name;
    return len > DNS_NAME_MAX ? DNS_OK_NAME_TOO_LONG : DNS_OK;

error:
    free (name);
    return err;
}

// Expands the name at src into out (room for cap octets) and stores its full length in
// *out_len; octets past cap are counted but not copied. Pointers only go back to label starts
// of earlier names, so each name is followed at most once and the length is bounded by the
// message size.
static dns_error_t
expand (const dns_parser_t *p,
        const uint8_t      *src,
        size_t              end,
        size_t              limit,
        uint8_t            *out,
        size_t              cap,
        size_t             *out_len)
{
    size_t pos   = 0;
    size_t len   = 0;
    size_t bound = limit;

    for (;;)
    {
        if (pos >= end) return DNS_ERR_TRUNCATED;

        const uint8_t *label = src + pos;
        size_t         size  = dns_label_size (label);
        switch (dns_label_type (label))
        {
        case DNS_LABEL_TYPE_NORMAL:
            if (end - pos < size) return DNS_ERR_TRUNCATED;
            if (len + size <= cap) memcpy (out + len, label, size);
            len += size;
            pos += size;
            if (label[0] == 0)
            {
                *out_len = len;
                return len > DNS_NAME_MAX ? DNS_OK_NAME_TOO_LONG : DNS_OK;
            }
            break;
        case DNS_LABEL_TYPE_POINTER:
        {
            size_t      target;
            dns_error_t err = check_pointer (p, label, end - pos, bound, &target);
            if (err != DNS_OK) return err;
            bound = target;
            src   = p->cur.buf;
            end   = limit;
            pos   = target;
            break;
        }
        default:
            return DNS_ERR_RESERVED_LABEL;
        }
    }
}

dns_error_t
dns_name_expand_length (const dns_parser_t *p, const dns_name_t *name, size_t *len)
{
    return expand (p, name->ptr, name->len, p->cur.len, NULL, 0, len);
}

dns_error_t
dns_name_expand (
    const dns_parser_t *p, const dns_name_t *name, uint8_t *buf, size_t len, dns_name_t *out)
{
    size_t      n;
    dns_error_t err = expand (p, name->ptr, name->len, p->cur.len, buf, len, &n);
    if (!dns_is_ok (err)) return err;
    if (n > len) return DNS_ERR_NO_SPACE;

    out->ptr = buf;
    out->len = n;
    return err;
}

static bool
labels_equal (const uint8_t *a, const uint8_t *b)
{
    for (;;)
    {
        if (!dns_label_equal (a, b)) return false;
        if (a[0] == 0) return true;
        a += dns_label_size (a);
        b += dns_label_size (b);
    }
}

static bool
find_suffix (
    const dns_parser_t *p, size_t nbytes_off, const uint8_t *suffix, size_t len, size_t *target)
{
    size_t limit = nbytes_off < DNS_LABEL_POINTER_MAX + 1 ? nbytes_off : DNS_LABEL_POINTER_MAX + 1;
    for (size_t t = 0; t < limit; t++)
    {
        uint8_t name[DNS_NAME_MAX];
        size_t  n;
        // Only names that fit in name[] can match; longer ones are not compressed.
        if (dns_parser_test_label (p, t) &&
            dns_is_ok (
                expand (p, p->cur.buf + t, nbytes_off - t, nbytes_off, name, sizeof name, &n)) &&
            n == len && n <= sizeof name && labels_equal (name, suffix))
        {
            *target = t;
            return true;
        }
    }
    return false;
}

static dns_error_t
check_labels (const dns_name_t *name)
{
    size_t end = 0;
    for (;;)
    {
        if (end >= name->len) return DNS_ERR_TRUNCATED;
        const uint8_t *label = name->ptr + end;
        if (dns_label_type (label) == DNS_LABEL_TYPE_POINTER) return DNS_ERR_COMPRESSED;
        if (dns_label_type (label) != DNS_LABEL_TYPE_NORMAL) return DNS_ERR_RESERVED_LABEL;
        end += dns_label_size (label);
        if (label[0] == 0) break;
    }
    return end == name->len ? DNS_OK : DNS_ERR_TRUNCATED;
}

dns_error_t
dns_name_to_bytes (dns_parser_t *p, const dns_name_t *name)
{
    assert (cursor_is_aligned (&p->cur));

    const uint8_t *d     = name->ptr;
    size_t         start = cursor_bytes (&p->cur);

    dns_parser_clear_labels (p, start);

    dns_error_t err = check_labels (name);
    if (err != DNS_OK) return err;
    if (cursor_is_overflow (&p->cur)) return DNS_ERR_NO_SPACE;

    size_t i      = 0;
    size_t target = 0;
    bool   found  = false;
    for (; d[i] != 0; i += dns_label_size (d + i))
        if ((found = find_suffix (p, start, d + i, name->len - i, &target))) break;
    if (!found) i = name->len;

    size_t n = found ? i + DNS_LABEL_POINTER_SIZE : i;
    if (!cursor_fits_bytes (&p->cur, n)) return DNS_ERR_NO_SPACE;

    uint8_t *ptr = cursor_ptr (&p->cur);
    memcpy (ptr, d, i);
    if (found) dns_label_pointer_write (ptr + i, target);

    for (size_t j = 0; j < i; j += dns_label_size (d + j))
        dns_parser_mark_label (p, start + j);
    cursor_add_bytes (&p->cur, n);
    return name->len > DNS_NAME_MAX ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

dns_error_t
dns_name_to_string (const dns_name_t *name, char *buf, size_t len)
{
    const uint8_t *d = name->ptr;

    if (len > 0) buf[0] = '\0';

    dns_error_t err = check_labels (name);
    if (err != DNS_OK) return err;

    if (len == 0) return DNS_ERR_NO_SPACE;

    size_t out = 0;
    size_t i   = 0;
    do
    {
        if (dns_label_to_string (d + i, buf, len, &out) != DNS_OK || len - out < 2) goto no_space;
        buf[out++] = '.';
        buf[out]   = '\0';
        i += dns_label_size (d + i);
    } while (i + 1 < name->len);
    return DNS_OK;

no_space:
    buf[0] = '\0';
    return DNS_ERR_NO_SPACE;
}

const char *
dns_name_debug_r (const dns_name_t *name, char *buf, size_t len)
{
    const uint8_t *d = name->ptr;

    if (len == 0) return buf;
    buf[0] = '\0';

    size_t i = 0;
    while (i < name->len && d[i] != 0 && dns_label_type (d + i) == DNS_LABEL_TYPE_NORMAL)
        i += dns_label_size (d + i);
    if (i + 1 >= name->len || dns_label_type (d + i) != DNS_LABEL_TYPE_POINTER)
    {
        dns_name_to_string (name, buf, len);
        return buf;
    }

    size_t out = 0;
    for (size_t j = 0; j < i; j += dns_label_size (d + j))
    {
        if (dns_label_to_string (d + j, buf, len, &out) != DNS_OK || len - out < 2)
        {
            buf[0] = '\0';
            return buf;
        }
        buf[out++] = '.';
        buf[out]   = '\0';
    }
    snprintf (buf + out, len - out, "[pointer 0x%04X]", (unsigned)dns_label_pointer_target (d + i));
    return buf;
}
