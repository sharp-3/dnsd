#include <stdio.h>
#include <string.h>

#include "dns/rdata.h"
#include "dns/record.h"
#include "packet/cursor.h"

#define RR_TTL_SIZE 4
#define RR_RDLENGTH_SIZE 2

dns_error_t
dns_record_from_bytes (dns_cursor_t *p, dns_record_t *out)
{
    cursor_t start = p->cur;

    dns_name_ref_t name;
    dns_error_t    err = dns_name_from_bytes (p, &name);
    if (!dns_is_ok (err)) return err;
    dns_error_t soft = err;

    dns_type_t  type     = take_bits (&p->cur, DNS_TYPE_SIZE * 8);
    dns_class_t class    = take_bits (&p->cur, DNS_CLASS_SIZE * 8);
    uint32_t    ttl      = take_bits (&p->cur, RR_TTL_SIZE * 8);
    uint16_t    rdlength = take_bits (&p->cur, RR_RDLENGTH_SIZE * 8);

    // The fields above and RDLENGTH octets of RDATA must be in the message.
    if (cursor_is_overflow (&p->cur) || !cursor_fits (&p->cur, rdlength, 0))
    {
        err = DNS_ERR_TRUNCATED;
        goto fail;
    }

    // The RDATA must take exactly RDLENGTH octets. It is read with the message cut after them,
    // so that running past them (in a field or a name) fails as truncated instead of reading
    // the next record's octets.
    size_t      rdata_start = cursor_bytes (&p->cur);
    size_t      msg_len     = p->cur.len;
    dns_rdata_t rdata;
    p->cur.len = rdata_start + rdlength;
    err        = dns_rdata_from_bytes (p, type, class, rdlength, &rdata);
    p->cur.len = msg_len;
    if (err == DNS_ERR_TRUNCATED || err == DNS_ERR_NAME_TRUNCATED) err = DNS_ERR_BAD_RDATA;
    if (dns_is_ok (err) && cursor_bytes (&p->cur) - rdata_start != rdlength)
        err = DNS_ERR_BAD_RDATA;
    if (!dns_is_ok (err)) goto fail;

    *out = (dns_record_t){.name = name, .type = type, .class = class, .ttl = ttl, .rdata = rdata};
    return dns_merge_soft (soft, err);

fail:
    // The names read may have marked label starts past the record (an RDATA name can run past
    // RDLENGTH): the rewind unmarks them.
    dns_cursor_rewind (p, &start);
    return err;
}

dns_error_t
dns_record_to_bytes (dns_cursor_t *p, const dns_record_t *rr, bool compress)
{
    cursor_t    start = p->cur;
    dns_error_t err   = dns_name_to_bytes (p, &rr->name, compress);
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
    {
        err = DNS_ERR_NO_SPACE;
        goto fail;
    }

    size_t rdata_start = cursor_bytes (&p->cur);
    err                = dns_rdata_to_bytes (p, rr->type, rr->class, &rr->rdata, compress);
    if (!dns_is_ok (err)) goto fail;
    size_t rdlength = cursor_bytes (&p->cur) - rdata_start;
    if (UINT16_MAX < rdlength)
    {
        err = DNS_ERR_BAD_RDATA;
        goto fail;
    }
    write_bits (&rdlength_at, RR_RDLENGTH_SIZE * 8, rdlength);
    return dns_merge_soft (soft, err);

fail:
    dns_cursor_rewind (p, &start);
    return err;
}

const char *
dns_record_debug_r (const dns_record_t *rr, char *buf, size_t len)
{
    if (len == 0) return buf;

    // The name goes straight into buf, so that a name of any length shows when buf has room.
    size_t n = strlen (dns_name_debug_r (&rr->name, buf, len));
    int    m = snprintf (buf + n,
                      len - n,
                      "\t%lu\t%s\t%s\t",
                      (unsigned long)rr->ttl,
                      dns_class_display (rr->class),
                      dns_type_display (rr->type));
    if (m < 0) buf[n] = '\0';
    if (m < 0 || len - n <= (size_t)m) return buf;
    n += m;

    dns_rdata_debug_r (rr->type, rr->class, &rr->rdata, buf + n, len - n);
    return buf;
}
