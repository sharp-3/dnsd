#include <stdio.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_soa_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_soa_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_soa_t rd;
    err = dns_name_from_bytes (p, &rd.mname);
    if (dns_is_ok (err)) err = dns_merge_soft (err, dns_name_from_bytes (p, &rd.rname));
    rd.serial  = take_bits (&p->cur, 32);
    rd.refresh = take_bits (&p->cur, 32);
    rd.retry   = take_bits (&p->cur, 32);
    rd.expire  = take_bits (&p->cur, 32);
    rd.minimum = take_bits (&p->cur, 32);
    err        = rdata_end (p, &start, err);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_soa_to_bytes (dns_cursor_t *p, const dns_rdata_soa_t *rd)
{
    cursor_t    start = p->cur;
    dns_error_t err   = dns_name_to_bytes (p, &rd->mname);
    if (dns_is_ok (err)) err = dns_merge_soft (err, dns_name_to_bytes (p, &rd->rname));
    emit_bits (&p->cur, 32, rd->serial);
    emit_bits (&p->cur, 32, rd->refresh);
    emit_bits (&p->cur, 32, rd->retry);
    emit_bits (&p->cur, 32, rd->expire);
    emit_bits (&p->cur, 32, rd->minimum);
    return rdata_put_end (p, &start, err);
}

// mname, then rname, one after the other in buf.
dns_error_t
dns_rdata_soa_expand (const dns_cursor_t    *p,
                      const dns_rdata_soa_t *rdata,
                      uint8_t               *buf,
                      size_t                 len,
                      dns_rdata_soa_t       *out)
{
    dns_rdata_soa_t rd  = *rdata;
    dns_error_t     err = dns_name_expand (p, &rdata->mname, buf, len, &rd.mname);
    if (!dns_is_ok (err)) return err;
    dns_error_t rerr =
        dns_name_expand (p, &rdata->rname, buf + rd.mname.len, len - rd.mname.len, &rd.rname);
    if (!dns_is_ok (rerr)) return rerr;
    *out = rd;
    return dns_merge_soft (err, rerr);
}

// mname, then rname, one after the other in buf.
dns_error_t
dns_rdata_soa_compress (const dns_cursor_t    *p,
                        const dns_rdata_soa_t *rdata,
                        uint8_t               *buf,
                        size_t                 len,
                        dns_rdata_soa_t       *out)
{
    dns_rdata_soa_t rd  = *rdata;
    dns_error_t     err = dns_name_compress (p, &rdata->mname, buf, len, &rd.mname);
    if (!dns_is_ok (err)) return err;
    dns_error_t rerr =
        dns_name_compress (p, &rdata->rname, buf + rd.mname.len, len - rd.mname.len, &rd.rname);
    if (!dns_is_ok (rerr)) return rerr;
    *out = rd;
    return dns_merge_soft (err, rerr);
}

size_t
dns_rdata_soa_length (const dns_rdata_soa_t *rd)
{
    return rd->mname.len + rd->rname.len + 20;
}

void
rdata_soa_display (const dns_rdata_soa_t *rd, char *buf, size_t len)
{
    snprintf (buf,
              len,
              "%s %s %lu %lu %lu %lu %lu",
              dns_name_debug (&rd->mname),
              dns_name_debug (&rd->rname),
              (unsigned long)rd->serial,
              (unsigned long)rd->refresh,
              (unsigned long)rd->retry,
              (unsigned long)rd->expire,
              (unsigned long)rd->minimum);
}
