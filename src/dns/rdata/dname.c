#include "common.h"

dns_error_t
dns_rdata_dname_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_dname_t *out)
{
    return rdata_name_from_bytes (p, len, &out->target);
}

dns_error_t
dns_rdata_dname_to_bytes (dns_cursor_t *p, const dns_rdata_dname_t *rd)
{
    // The target must not be compressed (RFC 6672).
    dns_error_t err = dns_name_check_uncompressed (&rd->target);
    if (!dns_is_ok (err)) return err;
    return rdata_name_to_bytes (p, &rd->target);
}

dns_error_t
dns_rdata_dname_expand (const dns_cursor_t      *p,
                        const dns_rdata_dname_t *rdata,
                        dns_name_t              *name,
                        dns_rdata_dname_t       *out)
{
    dns_error_t err = dns_name_expand (p, &rdata->target, name);
    if (!dns_is_ok (err)) return err;

    *out        = *rdata;
    out->target = dns_name_to_ref (name);
    return err;
}

// Names in DNAME RDATA must not be compressed (RFC 6672): kept as given.
dns_error_t
dns_rdata_dname_compress (const dns_cursor_t      *p,
                          const dns_rdata_dname_t *rdata,
                          dns_name_t              *name,
                          dns_rdata_dname_t       *out)
{
    (void)p;
    (void)name;
    *out = *rdata;
    return DNS_OK;
}

size_t
dns_rdata_dname_length (const dns_rdata_dname_t *rd)
{
    return rd->target.len;
}

void
rdata_dname_display (const dns_rdata_dname_t *rd, char *buf, size_t len)
{
    rdata_name_display (&rd->target, buf, len);
}
