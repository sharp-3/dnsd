#include "dns/record.h"
#include "dns/rdata.h"
#include "packet/cursor.h"

#define RR_TTL_SIZE 4
#define RR_RDLENGTH_SIZE 2

dns_error_t
dns_record_from_wire (dns_cursor_t *p, dns_record_t *out)
{
    cursor_t start = p->cur;

    dns_name_ref_t name;
    dns_error_t    err = dns_name_from_wire (p, &name);
    if (!dns_is_ok (err)) return err;
    dns_error_t soft = err;

    dns_type_t  type     = take_bits (&p->cur, DNS_TYPE_SIZE * 8);
    dns_class_t class    = take_bits (&p->cur, DNS_CLASS_SIZE * 8);
    uint32_t    ttl      = take_bits (&p->cur, RR_TTL_SIZE * 8);
    uint16_t    rdlength = take_bits (&p->cur, RR_RDLENGTH_SIZE * 8);

    // The fields above and RDLENGTH octets of RDATA must be in the message.
    if (cursor_is_overflow (&p->cur) || !cursor_fits (&p->cur, rdlength, 0))
        return dns_cursor_rewind_return_error (start, p, DNS_ERR_TRUNCATED);

    // The RDATA must take exactly RDLENGTH octets. It is read with the message cut after them,
    // so that running past them (in a field or a name) fails as truncated instead of reading
    // the next record's octets.
    size_t      rdata_start = cursor_bytes (&p->cur);
    size_t      msg_len     = p->cur.len;
    dns_rdata_t rdata;
    p->cur.len = rdata_start + rdlength;
    err        = dns_rdata_from_wire (p, type, class, rdlength, &rdata);
    p->cur.len = msg_len;
    if (DNS_ERR_TRUNCATED == err || DNS_ERR_NAME_TRUNCATED == err) err = DNS_ERR_BAD_RDATA;
    if (dns_is_ok (err) && cursor_bytes (&p->cur) - rdata_start != rdlength)
        err = DNS_ERR_BAD_RDATA;
    // The names read may have marked label starts past the record (an RDATA name can run past
    // RDLENGTH): the rewind unmarks them.
    if (!dns_is_ok (err)) return dns_cursor_rewind_return_error (start, p, err);

    *out = (dns_record_t){.name = name, .type = type, .class = class, .ttl = ttl, .rdata = rdata};
    return dns_merge_soft (soft, err);
}

dns_error_t
dns_record_to_wire (dns_cursor_t *p, const dns_record_t *rr, bool compress)
{
    cursor_t    start = p->cur;
    dns_error_t err   = dns_name_to_wire (p, &rr->name, compress);
    if (!dns_is_ok (err)) return err;
    dns_error_t soft = err;

    // RDLENGTH is known only once the RDATA is written (its names may be compressed): written as 0
    // first, then set.
    emit_bits (&p->cur, DNS_TYPE_SIZE * 8, rr->type);
    emit_bits (&p->cur, DNS_CLASS_SIZE * 8, rr->class);
    emit_bits (&p->cur, RR_TTL_SIZE * 8, rr->ttl);
    cursor_t rdlength_at = p->cur;
    emit_bits (&p->cur, RR_RDLENGTH_SIZE * 8, 0);
    if (cursor_is_overflow (&p->cur))
        return dns_cursor_rewind_return_error (start, p, DNS_ERR_NO_SPACE);

    size_t rdata_start = cursor_bytes (&p->cur);
    err                = dns_rdata_to_wire (p, rr->type, rr->class, &rr->rdata, compress);
    if (!dns_is_ok (err)) return dns_cursor_rewind_return_error (start, p, err);
    size_t rdlength = cursor_bytes (&p->cur) - rdata_start;
    if (UINT16_MAX < rdlength) return dns_cursor_rewind_return_error (start, p, DNS_ERR_BAD_RDATA);
    write_bits (&rdlength_at, RR_RDLENGTH_SIZE * 8, rdlength);
    return dns_merge_soft (soft, err);
}

GString *
dns_record_debug (const dns_record_t *self, GString *gs)
{
    dns_name_debug (&self->name, gs);
    g_string_append_printf (gs, "\t%lu\t", (unsigned long)self->ttl);
    dns_class_to_string (self->class, gs);
    g_string_append_c (gs, '\t');
    dns_type_to_string (self->type, gs);
    g_string_append_c (gs, '\t');
    return dns_rdata_debug (&self->rdata, self->type, self->class, gs);
}
