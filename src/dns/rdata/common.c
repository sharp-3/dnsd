#include <stdio.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
rdata_begin (dns_cursor_t *p, size_t len, cursor_t *start)
{
    if (!cursor_fits_bytes (&p->cur, len)) return DNS_ERR_TRUNCATED;
    *start     = p->cur;
    p->cur.len = cursor_bytes (&p->cur) + len;
    return DNS_OK;
}

dns_error_t
rdata_end (dns_cursor_t *p, const cursor_t *start, dns_error_t err)
{
    bool whole = !cursor_is_overflow (&p->cur) && cursor_bytes (&p->cur) == p->cur.len;
    if (err == DNS_ERR_TRUNCATED || (dns_is_ok (err) && !whole)) err = DNS_ERR_BAD_RDATA;

    if (dns_is_ok (err)) p->cur.len = start->len;
    else p->cur = *start;
    return err;
}

dns_error_t
rdata_put_end (dns_cursor_t *p, const cursor_t *start)
{
    if (!cursor_is_overflow (&p->cur)) return DNS_OK;
    p->cur = *start;
    return DNS_ERR_NO_SPACE;
}

dns_error_t
rdata_name_from_bytes (dns_cursor_t *p, size_t len, dns_name_t *out)
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
rdata_name_to_bytes (dns_cursor_t *p, const dns_name_t *name)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, name->ptr, name->len);
    return rdata_put_end (p, &start);
}

void
rdata_name_display (const dns_name_t *name, char *buf, size_t len)
{
    snprintf (buf, len, "%s", dns_name_debug (name));
}
