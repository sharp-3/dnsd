#include <stdio.h>
#include <string.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_soa_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_soa_t *out)
{
    cursor_t start = p->cur;

    (void)len; // checked against RDLENGTH by the record
    dns_rdata_soa_t rd;
    dns_error_t     err = dns_name_from_bytes (p, &rd.mname);
    if (dns_is_ok (err)) err = dns_merge_soft (err, dns_name_from_bytes (p, &rd.rname));
    rd.serial  = take_bits (&p->cur, 32);
    rd.refresh = take_bits (&p->cur, 32);
    rd.retry   = take_bits (&p->cur, 32);
    rd.expire  = take_bits (&p->cur, 32);
    rd.minimum = take_bits (&p->cur, 32);
    err        = rdata_end (p, &start, err, DNS_ERR_TRUNCATED);
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
    return rdata_end (p, &start, err, DNS_ERR_NO_SPACE);
}

// RNAME may be compressed against MNAME too.
dns_error_t
dns_rdata_soa_to_bytes_with_compress (dns_cursor_t *p, const dns_rdata_soa_t *rd)
{
    cursor_t    start = p->cur;
    dns_error_t err   = dns_name_to_bytes_with_compress (p, &rd->mname);
    if (dns_is_ok (err))
        err = dns_merge_soft (err, dns_name_to_bytes_with_compress (p, &rd->rname));
    emit_bits (&p->cur, 32, rd->serial);
    emit_bits (&p->cur, 32, rd->refresh);
    emit_bits (&p->cur, 32, rd->retry);
    emit_bits (&p->cur, 32, rd->expire);
    emit_bits (&p->cur, 32, rd->minimum);
    return rdata_end (p, &start, err, DNS_ERR_NO_SPACE);
}

// MNAME into names[0], RNAME into names[1].
dns_error_t
dns_rdata_soa_to_uncompressed (const dns_cursor_t    *p,
                               const dns_rdata_soa_t *rdata,
                               dns_name_t             names[2],
                               dns_rdata_soa_t       *out)
{
    dns_error_t err = dns_name_to_uncompressed (p, &rdata->mname, &names[0]);
    if (!dns_is_ok (err)) return err;
    dns_error_t rerr = dns_name_to_uncompressed (p, &rdata->rname, &names[1]);
    if (!dns_is_ok (rerr)) return rerr;

    *out       = *rdata;
    out->mname = dns_name_to_ref (&names[0]);
    out->rname = dns_name_to_ref (&names[1]);
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
    if (len == 0) return;

    // The names go straight into buf, so that a name of any length shows when buf has room.
    size_t n = strlen (dns_name_debug_r (&rd->mname, buf, len));
    if (len - n < 2) return;
    buf[n++] = ' ';
    n += strlen (dns_name_debug_r (&rd->rname, buf + n, len - n));
    snprintf (buf + n,
              len - n,
              " %lu %lu %lu %lu %lu",
              (unsigned long)rd->serial,
              (unsigned long)rd->refresh,
              (unsigned long)rd->retry,
              (unsigned long)rd->expire,
              (unsigned long)rd->minimum);
}
