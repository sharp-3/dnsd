#include <stdio.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_srv_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_srv_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_srv_t rd;
    rd.priority = take_bits (&p->cur, 16);
    rd.weight   = take_bits (&p->cur, 16);
    rd.port     = take_bits (&p->cur, 16);
    err         = rdata_end (p, &start, dns_name_from_bytes (p, &rd.target));
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_srv_to_bytes (dns_cursor_t *p, const dns_rdata_srv_t *rd)
{
    cursor_t start = p->cur;
    emit_bits (&p->cur, 16, rd->priority);
    emit_bits (&p->cur, 16, rd->weight);
    emit_bits (&p->cur, 16, rd->port);
    return rdata_put_end (p, &start, dns_name_to_bytes (p, &rd->target));
}

dns_error_t
dns_rdata_srv_expand (const dns_cursor_t    *p,
                      const dns_rdata_srv_t *rdata,
                      dns_name_t            *name,
                      dns_rdata_srv_t       *out)
{
    dns_error_t err = dns_name_expand (p, &rdata->target, name);
    if (!dns_is_ok (err)) return err;

    *out        = *rdata;
    out->target = dns_name_to_ref (name);
    return err;
}

// Names in SRV RDATA must not be compressed (RFC 2782): kept as given.
dns_error_t
dns_rdata_srv_compress (const dns_cursor_t    *p,
                        const dns_rdata_srv_t *rdata,
                        dns_name_t            *name,
                        dns_rdata_srv_t       *out)
{
    (void)p;
    (void)name;
    *out = *rdata;
    return DNS_OK;
}

size_t
dns_rdata_srv_length (const dns_rdata_srv_t *rd)
{
    return 6 + rd->target.len;
}

void
rdata_srv_display (const dns_rdata_srv_t *rd, char *buf, size_t len)
{
    snprintf (buf,
              len,
              "%u %u %u %s",
              (unsigned)rd->priority,
              (unsigned)rd->weight,
              (unsigned)rd->port,
              dns_name_debug (&rd->target));
}
