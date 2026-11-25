#include <stdio.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_unknown_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_unknown_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_unknown_t rd;
    rd.data = cursor_ptr (&p->cur);
    rd.len  = len;
    cursor_add_bytes (&p->cur, len);
    err = rdata_end (p, &start, DNS_OK);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_unknown_to_bytes (dns_cursor_t *p, const dns_rdata_unknown_t *rd)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->data, rd->len);
    return rdata_put_end (p, &start, DNS_OK);
}

// No domain names: nothing to expand.
dns_error_t
dns_rdata_unknown_expand (const dns_cursor_t        *p,
                          const dns_rdata_unknown_t *rdata,
                          uint8_t                   *buf,
                          size_t                     len,
                          dns_rdata_unknown_t       *out)
{
    (void)p;
    (void)buf;
    (void)len;
    *out = *rdata;
    return DNS_OK;
}

// No domain names: nothing to compress.
dns_error_t
dns_rdata_unknown_compress (const dns_cursor_t        *p,
                            const dns_rdata_unknown_t *rdata,
                            uint8_t                   *buf,
                            size_t                     len,
                            dns_rdata_unknown_t       *out)
{
    (void)p;
    (void)buf;
    (void)len;
    *out = *rdata;
    return DNS_OK;
}

size_t
dns_rdata_unknown_length (const dns_rdata_unknown_t *rd)
{
    return rd->len;
}

void
rdata_unknown_display (const dns_rdata_unknown_t *rd, char *buf, size_t len)
{
    static const char hex[] = "0123456789abcdef";

    int    k = snprintf (buf, len, "\\# %zu", rd->len);
    size_t n = k < 0 ? 0 : (size_t)k < len ? (size_t)k : len - 1;
    for (size_t i = 0; i < rd->len && n + 1 < len; i++)
    {
        if (i == 0) buf[n++] = ' ';
        if (n + 1 < len) buf[n++] = hex[rd->data[i] >> 4];
        if (n + 1 < len) buf[n++] = hex[rd->data[i] & 0xf];
    }
    buf[n] = '\0';
}
