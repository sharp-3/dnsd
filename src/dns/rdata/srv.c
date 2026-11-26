#include <stdio.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_srv_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_srv_t *out)
{
    cursor_t start = p->cur;

    dns_rdata_srv_t rd;
    rd.priority = take_bits (&p->cur, 16);
    rd.weight   = take_bits (&p->cur, 16);
    rd.port     = take_bits (&p->cur, 16);
    (void)len; // checked against RDLENGTH by the record
    dns_error_t err = rdata_end (p, &start, dns_name_from_bytes (p, &rd.target), DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_srv_to_bytes (dns_cursor_t *p, const dns_rdata_srv_t *rd)
{
    // The target must not be compressed (RFC 2782).
    dns_error_t err = dns_name_check_uncompressed (&rd->target);
    if (!dns_is_ok (err)) return err;

    cursor_t start = p->cur;
    emit_bits (&p->cur, 16, rd->priority);
    emit_bits (&p->cur, 16, rd->weight);
    emit_bits (&p->cur, 16, rd->port);
    return rdata_end (p, &start, dns_name_to_bytes (p, &rd->target), DNS_ERR_NO_SPACE);
}

// The target must not be compressed (RFC 2782): written as by dns_rdata_srv_to_bytes.
dns_error_t
dns_rdata_srv_to_bytes_with_compress (dns_cursor_t *p, const dns_rdata_srv_t *rd)
{
    return dns_rdata_srv_to_bytes (p, rd);
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
