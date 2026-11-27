#include "common.h"

dns_error_t
dns_rdata_dname_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_dname_t *out)
{
    return rdata_name_from_bytes (p, len, &out->target);
}

dns_error_t
dns_rdata_dname_to_bytes (dns_cursor_t *p, const dns_rdata_dname_t *rd, bool compress)
{
    // The target must not be compressed (RFC 6672): written uncompressed whatever compress is;
    // dns_name_to_bytes rejects a compressed one.
    (void)compress;
    return rdata_name_to_bytes (p, &rd->target, false);
}

dns_error_t
dns_rdata_dname_to_uncompressed (const dns_cursor_t      *p,
                                 const dns_rdata_dname_t *rdata,
                                 dns_name_t              *name,
                                 dns_rdata_dname_t       *out)
{
    dns_error_t err = dns_name_to_uncompressed (p, &rdata->target, name);
    if (!dns_is_ok (err)) return err;

    *out        = *rdata;
    out->target = dns_name_to_ref (name);
    return err;
}

size_t
dns_rdata_dname_length (const dns_rdata_dname_t *rd)
{
    return rd->target.len;
}

void
rdata_dname_debug (const dns_rdata_dname_t *rd, char *buf, size_t len)
{
    rdata_name_debug (&rd->target, buf, len);
}
