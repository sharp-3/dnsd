#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_soa_from_wire (dns_cursor_t *p, size_t len, dns_rdata_soa_t *out)
{
    cursor_t start = p->cur;

    (void)len; // checked against RDLENGTH by the record
    dns_rdata_soa_t rd;
    dns_error_t     err = dns_name_from_wire (p, &rd.mname);
    if (dns_is_ok (err)) err = dns_merge_soft (err, dns_name_from_wire (p, &rd.rname));
    rd.serial  = take_bits (&p->cur, 32);
    rd.refresh = take_bits (&p->cur, 32);
    rd.retry   = take_bits (&p->cur, 32);
    rd.expire  = take_bits (&p->cur, 32);
    rd.minimum = take_bits (&p->cur, 32);
    err        = rdata_end (p, &start, err, DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

// With compress, RNAME may be compressed against MNAME too.
dns_error_t
dns_rdata_soa_to_wire (dns_cursor_t *p, const dns_rdata_soa_t *rd, bool compress)
{
    cursor_t    start = p->cur;
    dns_error_t err   = dns_name_to_wire (p, &rd->mname, compress);
    if (dns_is_ok (err)) err = dns_merge_soft (err, dns_name_to_wire (p, &rd->rname, compress));
    emit_bits (&p->cur, 32, rd->serial);
    emit_bits (&p->cur, 32, rd->refresh);
    emit_bits (&p->cur, 32, rd->retry);
    emit_bits (&p->cur, 32, rd->expire);
    emit_bits (&p->cur, 32, rd->minimum);
    return rdata_end (p, &start, err, DNS_ERR_NO_SPACE);
}

size_t
dns_rdata_soa_length (const dns_rdata_soa_t *rd)
{
    return rd->mname.len + rd->rname.len + 20;
}

void
rdata_soa_debug (const dns_rdata_soa_t *self, GString *gs)
{
    dns_name_debug (&self->mname, gs);
    g_string_append_c (gs, ' ');
    dns_name_debug (&self->rname, gs);
    g_string_append_printf (gs,
                            " %lu %lu %lu %lu %lu",
                            (unsigned long)self->serial,
                            (unsigned long)self->refresh,
                            (unsigned long)self->retry,
                            (unsigned long)self->expire,
                            (unsigned long)self->minimum);
}
