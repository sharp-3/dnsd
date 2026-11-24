#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <stdio.h>

#include "common.h"
#include "packet/cursor.h"

static dns_error_t
rdata_aaaa_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_aaaa_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_aaaa_t rd;
    take_bytes (&p->cur, rd.addr, sizeof rd.addr);
    err = rdata_end (p, &start, DNS_OK);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

bool
dns_rdata_aaaa_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_aaaa_t *out)
{
    if (p->err != DNS_OK) return false;
    dns_error_t warn = p->warn;
    return dns_cursor_finish (p, warn, rdata_aaaa_from_bytes (p, len, out));
}

static dns_error_t
rdata_aaaa_to_bytes (dns_cursor_t *p, const dns_rdata_aaaa_t *rd)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->addr, sizeof rd->addr);
    return rdata_put_end (p, &start);
}

bool
dns_rdata_aaaa_to_bytes (dns_cursor_t *p, const dns_rdata_aaaa_t *rd)
{
    if (p->err != DNS_OK) return false;
    dns_error_t warn = p->warn;
    return dns_cursor_finish (p, warn, rdata_aaaa_to_bytes (p, rd));
}

size_t
rdata_aaaa_length (const dns_rdata_aaaa_t *rd)
{
    return sizeof rd->addr;
}

void
rdata_aaaa_display (const dns_rdata_aaaa_t *rd, char *buf, size_t len)
{
    char addr[INET6_ADDRSTRLEN];
    if (!inet_ntop (AF_INET6, rd->addr, addr, sizeof addr))
    {
        rdata_unknown_display (
            &(dns_rdata_unknown_t){.data = rd->addr, .len = sizeof rd->addr}, buf, len);
        return;
    }
    snprintf (buf, len, "%s", addr);
}
