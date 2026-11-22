#include <stdio.h>

#include "dns/rdata.h"
#include "dns/record.h"
#include "packet/emit.h"
#include "packet/take.h"

#define RR_TTL_SIZE 4
#define RR_RDLENGTH_SIZE 2

dns_error_t
dns_record_from_bytes (dns_parser_t *p, dns_record_t *out)
{
    cursor_t start = p->cur;

    dns_name_t  name;
    dns_error_t err = dns_name_from_bytes (p, &name);
    if (!dns_is_ok (err)) return err;
    dns_error_t soft = err;

    dns_type_t  type     = take_bits (&p->cur, DNS_TYPE_SIZE * 8);
    dns_class_t class    = take_bits (&p->cur, DNS_CLASS_SIZE * 8);
    uint32_t    ttl      = take_bits (&p->cur, RR_TTL_SIZE * 8);
    uint16_t    rdlength = take_bits (&p->cur, RR_RDLENGTH_SIZE * 8);

    // Fails with DNS_ERR_TRUNCATED if the fields above overflowed.
    dns_rdata_t rdata;
    err = dns_rdata_from_bytes (p, type, class, rdlength, &rdata);
    if (!dns_is_ok (err))
    {
        p->cur = start;
        return err;
    }

    *out = (dns_record_t){.name = name, .type = type, .class = class, .ttl = ttl, .rdata = rdata};
    return dns_merge_soft (soft, err);
}

dns_error_t
dns_record_to_bytes (dns_parser_t *p, const dns_record_t *rr)
{
    cursor_t    start = p->cur;
    dns_error_t err   = dns_name_to_bytes (p, &rr->name);
    if (!dns_is_ok (err)) return err;
    dns_error_t soft = err;

    size_t rdlength = dns_rdata_length (rr->type, rr->class, &rr->rdata);
    if (rdlength > UINT16_MAX)
    {
        err = DNS_ERR_BAD_RDATA;
        goto fail;
    }

    emit_bits (&p->cur, DNS_TYPE_SIZE * 8, rr->type);
    emit_bits (&p->cur, DNS_CLASS_SIZE * 8, rr->class);
    emit_bits (&p->cur, RR_TTL_SIZE * 8, rr->ttl);
    emit_bits (&p->cur, RR_RDLENGTH_SIZE * 8, rdlength);
    if ((err = dns_rdata_to_bytes (p, rr->type, rr->class, &rr->rdata)) != DNS_OK) goto fail;
    return soft;

fail:
    p->cur = start;
    return err;
}

const char *
dns_record_display_r (const dns_record_t *rr, char *buf, size_t len)
{
    if (len == 0) return buf;

    int n = snprintf (buf,
                      len,
                      "%s\t%lu\t%s\t%s\t",
                      dns_name_debug (&rr->name),
                      (unsigned long)rr->ttl,
                      dns_class_display (rr->class),
                      dns_type_display (rr->type));
    if (n < 0) buf[0] = '\0';
    if (n < 0 || (size_t)n >= len) return buf;

    dns_rdata_display_r (rr->type, rr->class, &rr->rdata, buf + n, len - n);
    return buf;
}
