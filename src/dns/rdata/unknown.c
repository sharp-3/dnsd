#include <stdio.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_unknown_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_unknown_t *out)
{
    cursor_t start = p->cur;

    dns_rdata_unknown_t rd;
    rd.data = cursor_ptr (&p->cur);
    rd.len  = len;
    cursor_add (&p->cur, len, 0);
    dns_error_t err = rdata_end (p, &start, DNS_OK, DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

// No domain names: compress has no effect.
dns_error_t
dns_rdata_unknown_to_bytes (dns_cursor_t *p, const dns_rdata_unknown_t *rd, bool compress)
{
    (void)compress;
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->data, rd->len);
    return rdata_end (p, &start, DNS_OK, DNS_ERR_NO_SPACE);
}

// No domain names: nothing to uncompress.
dns_error_t
dns_rdata_unknown_to_uncompressed (const dns_cursor_t        *p,
                                   const dns_rdata_unknown_t *rdata,
                                   dns_rdata_unknown_t       *out)
{
    (void)p;
    *out = *rdata;
    return DNS_OK;
}

size_t
dns_rdata_unknown_length (const dns_rdata_unknown_t *rd)
{
    return rd->len;
}

void
rdata_unknown_debug (const dns_rdata_unknown_t *rd, char *buf, size_t len)
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
