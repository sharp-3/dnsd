#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "dns/label.h"
#include "dns/name.h"

// Checks the (whole) compression pointer at label: it must go back before offset bound to a
// recorded label start. Stores its target in *target.
static dns_error_t
check_pointer (const dns_cursor_t *p, const uint8_t *label, size_t bound, size_t *target)
{
    *target = dns_label_pointer_target (label);
    if (*target >= bound || !dns_cursor_test_label (p, *target)) return DNS_ERR_NAME_BAD_POINTER;
    return DNS_OK;
}

dns_name_ref_t
dns_name_to_ref (const dns_name_t *name)
{
    return (dns_name_ref_t){.ptr = name->ptr, .len = name->len};
}

dns_error_t
dns_name_to_owned (const dns_name_ref_t *ref, dns_name_t *out)
{
    if (ref->len > out->cap) return DNS_ERR_NO_SPACE;
    memmove (out->ptr, ref->ptr, ref->len); // ref may point into out
    out->len = ref->len;
    return ref->len > DNS_NAME_MAX ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

dns_error_t
dns_name_from_bytes (dns_cursor_t *p, dns_name_ref_t *out)
{
    size_t      len;
    dns_error_t err = dns_name_length (p, &len);
    if (!dns_is_ok (err)) return err;

    const uint8_t *ptr   = cursor_ptr (&p->cur);
    size_t         start = cursor_bytes (&p->cur);
    dns_cursor_clear_labels (p, start);

    // Record where the labels start (not the pointer) as targets for later names, as
    // dns_name_to_bytes does.
    dns_label_iter_t it;
    dns_label_iter_init (&it, ptr, len, 0);
    while (dns_label_iter_next (&it) && dns_label_type (it.label) == DNS_LABEL_TYPE_NORMAL)
        dns_cursor_mark_label (p, start + it.off);
    cursor_add_bytes (&p->cur, len);

    out->ptr = ptr;
    out->len = len;
    return err;
}

dns_error_t
dns_name_length (const dns_cursor_t *p, size_t *size)
{
    assert (cursor_is_aligned (&p->cur));
    if (cursor_is_overflow (&p->cur)) return DNS_ERR_NAME_TRUNCATED;

    size_t           start = cursor_bytes (&p->cur);
    dns_label_iter_t it;
    dns_label_iter_init (&it, p->cur.buf, p->cur.len, start);
    while (dns_label_iter_next (&it))
    {
        if (dns_label_type (it.label) != DNS_LABEL_TYPE_POINTER) continue;
        size_t      target;
        dns_error_t err = check_pointer (p, it.label, start, &target);
        if (err != DNS_OK) return err;
    }
    if (it.err != DNS_OK) return it.err;

    *size = it.pos - start;
    return *size > DNS_NAME_MAX ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

// Parses str (see dns_name_from_string) and stores the length of its wire form in *len; with
// buf, also writes that form there (the caller checked it fits).
static dns_error_t
name_parse (const char *str, uint8_t *buf, size_t *len)
{
    const char *s = strcmp (str, ".") == 0 ? str + 1 : str;
    size_t      n = 0;

    while (*s != '\0')
    {
        // One octet more than a label takes, so that a label too long is told apart.
        uint8_t     label[1 + DNS_LABEL_MAX + 1];
        dns_error_t err = dns_label_from_string (&s, label, sizeof label);
        if (err == DNS_ERR_NO_SPACE) return DNS_ERR_NAME_LABEL_TOO_LONG;
        if (err != DNS_OK) return err;
        if (label[0] == 0) return DNS_ERR_BAD_TEXT;
        if (buf) memcpy (buf + n, label, dns_label_size (label));
        n += dns_label_size (label);
        if (*s == '.') s++;
    }
    if (buf) buf[n] = 0;
    *len = n + 1;
    return DNS_OK;
}

dns_error_t
dns_name_from_string (const char *str, dns_name_t *out)
{
    // Check and measure first, so that out is left alone on any error.
    size_t      n;
    dns_error_t err = name_parse (str, NULL, &n);
    if (err != DNS_OK) return err;
    if (n > out->cap) return DNS_ERR_NO_SPACE;

    name_parse (str, out->ptr, &n);
    out->len = n;
    return n > DNS_NAME_MAX ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

// Expands the name at src into out (room for cap octets) and stores its full length in
// *out_len; octets past cap are counted but not copied. Pointers only go back to label starts
// of earlier names, so each name is followed at most once and the length is bounded by the
// message size.
static dns_error_t
expand (const dns_cursor_t *p,
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
        if (dns_label_type (it.label) == DNS_LABEL_TYPE_POINTER)
        {
            size_t      target;
            dns_error_t err = check_pointer (p, it.label, bound, &target);
            if (err != DNS_OK) return err;
            bound = target;
            dns_label_iter_init (&it, p->cur.buf, limit, target);
            continue;
        }
        size_t size = dns_label_size (it.label);
        if (len + size <= cap) memmove (out + len, it.label, size);
        len += size;
    }
    if (it.err != DNS_OK) return it.err;

    *out_len = len;
    return len > DNS_NAME_MAX ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

dns_error_t
dns_name_expand_length (const dns_cursor_t *p, const dns_name_ref_t *name, size_t *len)
{
    return expand (p, name->ptr, name->len, p->cur.len, NULL, 0, len);
}

dns_error_t
dns_name_expand (const dns_cursor_t *p, const dns_name_ref_t *name, dns_name_t *out)
{
    // Check and measure first, so that out is left alone on any error.
    size_t      n;
    dns_error_t err = expand (p, name->ptr, name->len, p->cur.len, NULL, 0, &n);
    if (!dns_is_ok (err)) return err;
    if (n > out->cap) return DNS_ERR_NO_SPACE;

    expand (p, name->ptr, name->len, p->cur.len, out->ptr, out->cap, &n);
    out->len = n;
    return err;
}

// Whether the uncompressed names a and b, len octets each, are equal ignoring ASCII case.
static bool
labels_equal (const uint8_t *a, const uint8_t *b, size_t len)
{
    dns_label_iter_t ia, ib;
    dns_label_iter_init (&ia, a, len, 0);
    dns_label_iter_init (&ib, b, len, 0);
    while (dns_label_iter_next (&ia))
        if (!dns_label_iter_next (&ib) || !dns_label_equal (ia.label, ib.label)) return false;
    return ia.err == DNS_OK;
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
        // Only names that fit in name[] can match; longer ones are not compressed.
        if (dns_cursor_test_label (p, t) &&
            dns_is_ok (
                expand (p, p->cur.buf + t, nbytes_off - t, nbytes_off, name, sizeof name, &n)) &&
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
        if (dns_label_type (it.label) == DNS_LABEL_TYPE_POINTER) return DNS_ERR_NAME_COMPRESSED;
    if (it.err != DNS_OK) return it.err;
    if (it.pos != name->len) return DNS_ERR_NAME_TRAILING_DATA;
    return name->len > DNS_NAME_MAX ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

// Records where the labels of the name just written at the position (n octets) start (not the
// pointer) as targets for later names, and moves past it.
static void
mark_written (dns_cursor_t *p, size_t n)
{
    size_t           start = cursor_bytes (&p->cur);
    dns_label_iter_t it;
    dns_label_iter_init (&it, cursor_ptr (&p->cur), n, 0);
    while (dns_label_iter_next (&it) && dns_label_type (it.label) == DNS_LABEL_TYPE_NORMAL)
        dns_cursor_mark_label (p, start + it.off);
    cursor_add_bytes (&p->cur, n);
}

dns_error_t
dns_name_to_bytes (dns_cursor_t *p, const dns_name_ref_t *name)
{
    assert (cursor_is_aligned (&p->cur));

    size_t start = cursor_bytes (&p->cur);
    dns_cursor_clear_labels (p, start);

    // The labels must be whole, and a pointer (which ends the name) must go back to a label
    // start already written.
    dns_label_iter_t it;
    dns_label_iter_init (&it, name->ptr, name->len, 0);
    while (dns_label_iter_next (&it))
    {
        if (dns_label_type (it.label) != DNS_LABEL_TYPE_POINTER) continue;
        size_t      target;
        dns_error_t err = check_pointer (p, it.label, start, &target);
        if (err != DNS_OK) return err;
    }
    if (it.err != DNS_OK) return it.err;
    if (it.pos != name->len) return DNS_ERR_NAME_TRAILING_DATA;

    if (!cursor_fits_bytes (&p->cur, name->len)) return DNS_ERR_NO_SPACE;
    memcpy (cursor_ptr (&p->cur), name->ptr, name->len);
    mark_written (p, name->len);
    return name->len > DNS_NAME_MAX ? DNS_OK_NAME_TOO_LONG : DNS_OK;
}

dns_error_t
dns_name_to_bytes_with_compress (dns_cursor_t *p, const dns_name_ref_t *name)
{
    assert (cursor_is_aligned (&p->cur));

    dns_error_t err = dns_name_check_uncompressed (name);
    if (!dns_is_ok (err)) return err;

    size_t start = cursor_bytes (&p->cur);
    dns_cursor_clear_labels (p, start);

    // i: octets kept as labels; the rest (if found earlier in the message) becomes a pointer to
    // target. The leftmost suffix found is the longest one.
    size_t           i      = name->len;
    size_t           target = 0;
    bool             found  = false;
    dns_label_iter_t it;
    dns_label_iter_init (&it, name->ptr, name->len, 0);
    while (dns_label_iter_next (&it) && it.label[0] != 0)
    {
        if ((found = find_suffix (p, start, it.label, name->len - it.off, &target)))
        {
            i = it.off;
            break;
        }
    }

    size_t n = found ? i + DNS_LABEL_POINTER_SIZE : i;
    if (!cursor_fits_bytes (&p->cur, n)) return DNS_ERR_NO_SPACE;
    memcpy (cursor_ptr (&p->cur), name->ptr, i);
    if (found) dns_label_pointer_write (cursor_ptr (&p->cur) + i, target);
    mark_written (p, n);
    return err;
}

dns_error_t
dns_name_to_string (const dns_name_ref_t *name, char *buf, size_t len)
{
    if (len > 0) buf[0] = '\0';

    dns_error_t err = dns_name_check_uncompressed (name);
    if (!dns_is_ok (err)) return err;

    if (len == 0) return DNS_ERR_NO_SPACE;

    // Each label followed by a dot; the root label only shows when it is the whole name (".").
    size_t           out = 0;
    dns_label_iter_t it;
    dns_label_iter_init (&it, name->ptr, name->len, 0);
    while (dns_label_iter_next (&it))
    {
        if (it.label[0] == 0 && it.off != 0) break;
        if (dns_label_to_string (it.label, buf, len, &out) != DNS_OK || len - out < 2)
            goto no_space;
        buf[out++] = '.';
        buf[out]   = '\0';
    }
    return DNS_OK;

no_space:
    buf[0] = '\0';
    return DNS_ERR_NO_SPACE;
}

const char *
dns_name_debug_r (const dns_name_ref_t *name, char *buf, size_t len)
{
    if (len == 0) return buf;
    buf[0] = '\0';

    // Find the pointer ending the name; without one, it is shown like dns_name_to_string.
    dns_label_iter_t it;
    dns_label_iter_init (&it, name->ptr, name->len, 0);
    while (dns_label_iter_next (&it) && dns_label_type (it.label) == DNS_LABEL_TYPE_NORMAL)
        ;
    if (it.err != DNS_OK || dns_label_type (it.label) != DNS_LABEL_TYPE_POINTER)
    {
        dns_name_to_string (name, buf, len);
        return buf;
    }

    const uint8_t *pointer = it.label;
    size_t         out     = 0;
    dns_label_iter_init (&it, name->ptr, name->len, 0);
    while (dns_label_iter_next (&it) && it.label != pointer)
    {
        if (dns_label_to_string (it.label, buf, len, &out) != DNS_OK || len - out < 2)
        {
            buf[0] = '\0';
            return buf;
        }
        buf[out++] = '.';
        buf[out]   = '\0';
    }
    snprintf (
        buf + out, len - out, "[pointer 0x%04X]", (unsigned)dns_label_pointer_target (pointer));
    return buf;
}
