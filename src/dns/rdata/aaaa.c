#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <stdio.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_aaaa_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_aaaa_t *out)
{
    cursor_t start = p->cur;

    dns_rdata_aaaa_t rd;
    take_bytes (&p->cur, rd.addr, sizeof rd.addr);
    (void)len; // checked against RDLENGTH by the record
    dns_error_t err = rdata_end (p, &start, DNS_OK, DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

// No domain names: compress has no effect.
dns_error_t
dns_rdata_aaaa_to_bytes (dns_cursor_t *p, const dns_rdata_aaaa_t *rd, bool compress)
{
    (void)compress;
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->addr, sizeof rd->addr);
    return rdata_end (p, &start, DNS_OK, DNS_ERR_NO_SPACE);
}

// No domain names: nothing to uncompress.
dns_error_t
dns_rdata_aaaa_to_uncompressed (const dns_cursor_t     *p,
                                const dns_rdata_aaaa_t *rdata,
                                dns_rdata_aaaa_t       *out)
{
    (void)p;
    *out = *rdata;
    return DNS_OK;
}

size_t
dns_rdata_aaaa_length (const dns_rdata_aaaa_t *rd)
{
    return sizeof rd->addr;
}

void
rdata_aaaa_debug (const dns_rdata_aaaa_t *rd, char *buf, size_t len)
{
    char addr[INET6_ADDRSTRLEN];
    if (!inet_ntop (AF_INET6, rd->addr, addr, sizeof addr))
    {
        rdata_unknown_debug (
            &(dns_rdata_unknown_t){.data = rd->addr, .len = sizeof rd->addr}, buf, len);
        return;
    }
    snprintf (buf, len, "%s", addr);
}
