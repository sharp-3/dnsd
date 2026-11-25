#include "common.h"

dns_error_t
dns_rdata_ptr_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_ptr_t *out)
{
    return rdata_name_from_bytes (p, len, &out->ptrdname);
}

dns_error_t
dns_rdata_ptr_to_bytes (dns_cursor_t *p, const dns_rdata_ptr_t *rd)
{
    return rdata_name_to_bytes (p, &rd->ptrdname);
}

dns_error_t
dns_rdata_ptr_expand (const dns_cursor_t    *p,
                      const dns_rdata_ptr_t *rdata,
                      uint8_t               *buf,
                      size_t                 len,
                      dns_rdata_ptr_t       *out)
{
    dns_rdata_ptr_t rd  = *rdata;
    dns_error_t     err = dns_name_expand (p, &rdata->ptrdname, buf, len, &rd.ptrdname);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_ptr_compress (const dns_cursor_t    *p,
                        const dns_rdata_ptr_t *rdata,
                        uint8_t               *buf,
                        size_t                 len,
                        dns_rdata_ptr_t       *out)
{
    dns_rdata_ptr_t rd  = *rdata;
    dns_error_t     err = dns_name_compress (p, &rdata->ptrdname, buf, len, &rd.ptrdname);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

size_t
dns_rdata_ptr_length (const dns_rdata_ptr_t *rd)
{
    return rd->ptrdname.len;
}

void
rdata_ptr_display (const dns_rdata_ptr_t *rd, char *buf, size_t len)
{
    rdata_name_display (&rd->ptrdname, buf, len);
}
