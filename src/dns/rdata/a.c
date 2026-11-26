#include <stdio.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_a_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_a_t *out)
{
    cursor_t start = p->cur;

    dns_rdata_a_t rd;
    take_bytes (&p->cur, rd.addr, sizeof rd.addr);
    (void)len; // checked against RDLENGTH by the record
    dns_error_t err = rdata_end (p, &start, DNS_OK, DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_a_to_bytes (dns_cursor_t *p, const dns_rdata_a_t *rd)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->addr, sizeof rd->addr);
    return rdata_end (p, &start, DNS_OK, DNS_ERR_NO_SPACE);
}

// No domain names: written as by dns_rdata_a_to_bytes.
dns_error_t
dns_rdata_a_to_bytes_with_compress (dns_cursor_t *p, const dns_rdata_a_t *rd)
{
    return dns_rdata_a_to_bytes (p, rd);
}

// No domain names: nothing to expand.
dns_error_t
dns_rdata_a_expand (const dns_cursor_t *p, const dns_rdata_a_t *rdata, dns_rdata_a_t *out)
{
    (void)p;
    *out = *rdata;
    return DNS_OK;
}

size_t
dns_rdata_a_length (const dns_rdata_a_t *rd)
{
    return sizeof rd->addr;
}

void
rdata_a_display (const dns_rdata_a_t *rd, char *buf, size_t len)
{
    const uint8_t *a = rd->addr;
    snprintf (buf, len, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}
