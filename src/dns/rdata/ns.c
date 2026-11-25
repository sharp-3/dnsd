#include "common.h"

dns_error_t
dns_rdata_ns_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_ns_t *out)
{
    return rdata_name_from_bytes (p, len, &out->nsdname);
}

dns_error_t
dns_rdata_ns_to_bytes (dns_cursor_t *p, const dns_rdata_ns_t *rd)
{
    return rdata_name_to_bytes (p, &rd->nsdname);
}

dns_error_t
dns_rdata_ns_expand (const dns_cursor_t   *p,
                     const dns_rdata_ns_t *rdata,
                     dns_name_t           *name,
                     dns_rdata_ns_t       *out)
{
    dns_error_t err = dns_name_expand (p, &rdata->nsdname, name);
    if (!dns_is_ok (err)) return err;

    *out         = *rdata;
    out->nsdname = dns_name_to_ref (name);
    return err;
}

dns_error_t
dns_rdata_ns_compress (const dns_cursor_t   *p,
                       const dns_rdata_ns_t *rdata,
                       dns_name_t           *name,
                       dns_rdata_ns_t       *out)
{
    dns_error_t err = dns_name_compress (p, &rdata->nsdname, name);
    if (!dns_is_ok (err)) return err;

    *out         = *rdata;
    out->nsdname = dns_name_to_ref (name);
    return err;
}

size_t
dns_rdata_ns_length (const dns_rdata_ns_t *rd)
{
    return rd->nsdname.len;
}

void
rdata_ns_display (const dns_rdata_ns_t *rd, char *buf, size_t len)
{
    rdata_name_display (&rd->nsdname, buf, len);
}
