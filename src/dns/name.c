#include <assert.h>
#include <string.h>

#include "dns/label.h"
#include "dns/name.h"

static dns_error_t
check_pointer (const dns_cursor_t *p, const uint8_t *label, size_t bound, size_t *target)
{
    *target = dns_label_pointer_target (label);
    if (bound <= *target || !dns_cursor_test_label (p, *target)) return DNS_ERR_NAME_BAD_POINTER;
    return DNS_OK;
}

dns_error_t
dns_name_to_ref (const dns_name_t *self, dns_name_ref_t *value)
{
    *value = (dns_name_ref_t){.ptr = self->ptr, .len = self->len};
    return DNS_OK;
}

dns_error_t
dns_name_from_ref (dns_name_t *self, const dns_name_ref_t *value)
{
    if (self->cap < value->len) return DNS_ERR_NO_SPACE;
    memmove (self->ptr, value->ptr, value->len); // value may point into self
    self->len = value->len;
    return DNS_NAME_MAX < value->len ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

static dns_error_t
name_length (const dns_cursor_t *p, size_t *size)
{
    assert (cursor_is_aligned (&p->cur));
    if (cursor_is_overflow (&p->cur)) return DNS_ERR_NAME_TRUNCATED;

    size_t           start = cursor_bytes (&p->cur);
    dns_label_iter_t it;
    dns_label_iter_init (&it, p->cur.buf, p->cur.len, start);
    while (dns_label_iter_next (&it))
    {
        if (DNS_LABEL_TYPE_POINTER != dns_label_type (it.label)) continue;
        size_t      target;
        dns_error_t err = check_pointer (p, it.label, start, &target);
        if (DNS_OK != err) return err;
    }
    if (DNS_OK != it.err) return it.err;

    *size = it.pos - start;
    return DNS_NAME_MAX < *size ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

dns_error_t
dns_name_from_wire (dns_cursor_t *p, dns_name_ref_t *out)
{
    size_t      len;
    dns_error_t err = name_length (p, &len);
    if (!dns_is_ok (err)) return err;

    const uint8_t *ptr   = cursor_ptr (&p->cur);
    size_t         start = cursor_bytes (&p->cur);
    dns_cursor_clear_labels (p, start);

    dns_label_iter_t it;
    dns_label_iter_init (&it, ptr, len, 0);
    while (dns_label_iter_next (&it))
        dns_cursor_mark_label (p, start + it.off);
    cursor_add (&p->cur, len, 0);

    out->ptr = ptr;
    out->len = len;
    return err;
}

static dns_error_t
name_parse (const char *str, uint8_t *buf, size_t *len)
{
    const char *s = 0 == strcmp (str, ".") ? str + 1 : str;
    size_t      n = 0;

    while ('\0' != *s)
    {
        uint8_t     label[1 + DNS_LABEL_MAX];
        dns_error_t err = dns_label_from_string (label, &s);
        if (DNS_OK != err) return err;
        if (0 == label[0]) return DNS_ERR_BAD_TEXT;
        if (NULL != buf) memcpy (buf + n, label, dns_label_size (label));
        n += dns_label_size (label);
        if ('.' == *s) s++;
    }
    if (NULL != buf) buf[n] = 0;
    *len = n + 1;
    return DNS_OK;
}

dns_error_t
dns_name_from_string (dns_name_t *self, const char *str)
{
    size_t      n;
    dns_error_t err = name_parse (str, NULL, &n);
    if (DNS_OK != err) return err;
    if (self->cap < n) return DNS_ERR_NO_SPACE;

    name_parse (str, self->ptr, &n);
    self->len = n;
    return DNS_NAME_MAX < n ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

static dns_error_t
to_uncompressed (const dns_cursor_t *p,
                 const uint8_t      *src,
                 size_t              end,
                 size_t              limit,
                 uint8_t            *out,
                 size_t              cap,
                 size_t             *out_len)
{
    size_t           len   = 0;
    size_t           bound = limit;
    dns_label_iter_t it;
    dns_label_iter_init (&it, src, end, 0);
    while (dns_label_iter_next (&it))
    {
        if (DNS_LABEL_TYPE_POINTER == dns_label_type (it.label))
        {
            size_t      target;
            dns_error_t err = check_pointer (p, it.label, bound, &target);
            if (DNS_OK != err) return err;
            bound = target;
            dns_label_iter_init (&it, p->cur.buf, limit, target);
            continue;
        }
        size_t size = dns_label_size (it.label);
        if (len + size <= cap) memmove (out + len, it.label, size);
        len += size;
    }
    if (DNS_OK != it.err) return it.err;

    *out_len = len;
    return DNS_NAME_MAX < len ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

dns_error_t
dns_name_to_uncompressed_length (const dns_cursor_t *p, const dns_name_ref_t *name, size_t *len)
{
    return to_uncompressed (p, name->ptr, name->len, p->cur.len, NULL, 0, len);
}

dns_error_t
dns_name_to_uncompressed (const dns_name_ref_t *self, const dns_cursor_t *p, dns_name_t *value)
{
    size_t      n;
    dns_error_t err = to_uncompressed (p, self->ptr, self->len, p->cur.len, NULL, 0, &n);
    if (!dns_is_ok (err)) return err;
    if (value->cap < n) return DNS_ERR_NO_SPACE;

    to_uncompressed (p, self->ptr, self->len, p->cur.len, value->ptr, value->cap, &n);
    value->len = n;
    return err;
}

static bool
labels_equal (const uint8_t *a, const uint8_t *b, size_t len)
{
    dns_label_iter_t ia, ib;
    dns_label_iter_init (&ia, a, len, 0);
    dns_label_iter_init (&ib, b, len, 0);
    while (dns_label_iter_next (&ia))
        if (!dns_label_iter_next (&ib) || !dns_label_equal (ia.label, ib.label)) return false;
    return DNS_OK == ia.err;
}

static bool
find_suffix (
    const dns_cursor_t *p, size_t nbytes_off, const uint8_t *suffix, size_t len, size_t *target)
{
    size_t limit = nbytes_off < DNS_LABEL_POINTER_MAX + 1 ? nbytes_off : DNS_LABEL_POINTER_MAX + 1;
    for (size_t t = 0; t < limit; t++)
    {
        uint8_t name[DNS_NAME_MAX];
        size_t  n;
        if (dns_cursor_test_label (p, t) &&
            dns_is_ok (to_uncompressed (
                p, p->cur.buf + t, nbytes_off - t, nbytes_off, name, sizeof name, &n)) &&
            n == len && n <= sizeof name && labels_equal (name, suffix, len))
        {
            *target = t;
            return true;
        }
    }
    return false;
}

dns_error_t
dns_name_check_uncompressed (const dns_name_ref_t *name)
{
    dns_label_iter_t it;
    dns_label_iter_init (&it, name->ptr, name->len, 0);
    while (dns_label_iter_next (&it))
        if (DNS_LABEL_TYPE_POINTER == dns_label_type (it.label)) return DNS_ERR_NAME_COMPRESSED;
    if (DNS_OK != it.err) return it.err;
    if (it.pos != name->len) return DNS_ERR_NAME_TRAILING_DATA;
    return DNS_NAME_MAX < name->len ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

static void
mark_written (dns_cursor_t *p, size_t n)
{
    size_t           start = cursor_bytes (&p->cur);
    dns_label_iter_t it;
    dns_label_iter_init (&it, cursor_ptr (&p->cur), n, 0);
    while (dns_label_iter_next (&it) && DNS_LABEL_TYPE_NORMAL == dns_label_type (it.label) &&
           0 != it.label[0])
        dns_cursor_mark_label (p, start + it.off);
    cursor_add (&p->cur, n, 0);
}

dns_error_t
dns_name_to_wire (dns_cursor_t *p, const dns_name_ref_t *name, bool compress)
{
    assert (cursor_is_aligned (&p->cur));

    dns_error_t err = dns_name_check_uncompressed (name);
    if (!dns_is_ok (err)) return err;

    size_t start = cursor_bytes (&p->cur);
    dns_cursor_clear_labels (p, start);

    size_t i      = name->len;
    size_t target = 0;
    bool   found  = false;
    if (compress)
    {
        dns_label_iter_t it;
        dns_label_iter_init (&it, name->ptr, name->len, 0);
        while (dns_label_iter_next (&it) && 0 != it.label[0])
        {
            if ((found = find_suffix (p, start, it.label, name->len - it.off, &target)))
            {
                i = it.off;
                break;
            }
        }
    }

    size_t n = found ? i + DNS_LABEL_POINTER_SIZE : i;
    if (!cursor_fits (&p->cur, n, 0)) return DNS_ERR_NO_SPACE;
    memcpy (cursor_ptr (&p->cur), name->ptr, i);
    if (found) dns_label_pointer_write (cursor_ptr (&p->cur) + i, target);
    mark_written (p, n);
    return err;
}

static void
append_labels (const dns_name_ref_t *self, const uint8_t *stop, GString *gs)
{
    dns_label_iter_t it;
    dns_label_iter_init (&it, self->ptr, self->len, 0);
    while (dns_label_iter_next (&it) && it.label != stop)
    {
        if (0 == it.label[0] && 0 != it.off) break;
        dns_label_to_string (it.label, gs);
        g_string_append_c (gs, '.');
    }
}

dns_error_t
dns_name_to_string (const dns_name_ref_t *self, GString *gs)
{
    dns_error_t err = dns_name_check_uncompressed (self);
    if (!dns_is_ok (err)) return err;

    append_labels (self, NULL, gs);
    return DNS_OK;
}

GString *
dns_name_debug (const dns_name_ref_t *self, GString *gs)
{
    dns_label_iter_t it;
    dns_label_iter_init (&it, self->ptr, self->len, 0);
    while (dns_label_iter_next (&it) && DNS_LABEL_TYPE_NORMAL == dns_label_type (it.label))
        ;
    if (DNS_OK != it.err || DNS_LABEL_TYPE_POINTER != dns_label_type (it.label))
    {
        dns_name_to_string (self, gs);
        return gs;
    }

    append_labels (self, it.label, gs);
    g_string_append_printf (gs, "[pointer 0x%04X]", (unsigned)dns_label_pointer_target (it.label));
    return gs;
}
