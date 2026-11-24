#include <stdarg.h>
#include <stdio.h>

#include "common.h"
#include "packet/emit.h"

dns_error_t
rdata_begin (dns_parser_t *p, size_t len, cursor_t *start)
{
    if (!cursor_fits_bytes (&p->cur, len)) return DNS_ERR_TRUNCATED;
    *start     = p->cur;
    p->cur.len = cursor_bytes (&p->cur) + len;
    return DNS_OK;
}

dns_error_t
rdata_end (dns_parser_t *p, const cursor_t *start, dns_error_t err)
{
    bool whole = !cursor_is_overflow (&p->cur) && cursor_bytes (&p->cur) == p->cur.len;
    if (err == DNS_ERR_TRUNCATED || (dns_is_ok (err) && !whole)) err = DNS_ERR_BAD_RDATA;

    if (dns_is_ok (err)) p->cur.len = start->len;
    else p->cur = *start;
    return err;
}

dns_error_t
rdata_put_end (dns_parser_t *p, const cursor_t *start)
{
    if (!cursor_is_overflow (&p->cur)) return DNS_OK;
    p->cur = *start;
    return DNS_ERR_NO_SPACE;
}

dns_error_t
rdata_name_from_bytes (dns_parser_t *p, size_t len, dns_name_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_name_t name;
    err = rdata_end (p, &start, dns_name_from_bytes (p, &name));
    if (dns_is_ok (err)) *out = name;
    return err;
}

dns_error_t
rdata_name_to_bytes (dns_parser_t *p, const dns_name_t *name)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, name->ptr, name->len);
    return rdata_put_end (p, &start);
}

void
rdata_name_display (const dns_name_t *name, char *buf, size_t len, size_t *out)
{
    rdata_appendf (buf, len, out, "%s", dns_name_debug (name));
}

void
rdata_appendf (char *buf, size_t len, size_t *out, const char *fmt, ...)
{
    if (*out >= len) return;

    va_list ap;
    va_start (ap, fmt);
    int n = vsnprintf (buf + *out, len - *out, fmt, ap);
    va_end (ap);

    if (n < 0 || (size_t)n >= len - *out) *out = len;
    else *out += n;
}

void
rdata_append_string (char *buf, size_t len, size_t *out, const uint8_t *s, size_t n)
{
    rdata_appendf (buf, len, out, "\"");
    for (size_t i = 0; i < n; i++)
    {
        if (s[i] == '"' || s[i] == '\\') rdata_appendf (buf, len, out, "\\%c", s[i]);
        else if (s[i] < 0x20 || s[i] > 0x7e) rdata_appendf (buf, len, out, "\\%03u", s[i]);
        else rdata_appendf (buf, len, out, "%c", s[i]);
    }
    rdata_appendf (buf, len, out, "\"");
}
