#include "common.h"

dns_error_t
dns_rdata_ptr_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_ptr_t *out)
{
    return rdata_name_from_bytes (p, len, &out->ptrdname);
}

dns_error_t
dns_rdata_ptr_to_bytes (dns_cursor_t *p, const dns_rdata_ptr_t *rd, bool compress)
{
    return rdata_name_to_bytes (p, &rd->ptrdname, compress);
}

size_t
dns_rdata_ptr_length (const dns_rdata_ptr_t *rd)
{
    return rd->ptrdname.len;
}

void
rdata_ptr_debug (const dns_rdata_ptr_t *rd, char *buf, size_t len)
{
    rdata_name_debug (&rd->ptrdname, buf, len);
}
