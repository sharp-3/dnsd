#include "common.h"

dns_error_t
dns_rdata_mr_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_mr_t *out)
{
    return rdata_name_from_bytes (p, len, &out->newname);
}

dns_error_t
dns_rdata_mr_to_bytes (dns_cursor_t *p, const dns_rdata_mr_t *rd, bool compress)
{
    return rdata_name_to_bytes (p, &rd->newname, compress);
}

size_t
dns_rdata_mr_length (const dns_rdata_mr_t *rd)
{
    return rd->newname.len;
}

void
rdata_mr_debug (const dns_rdata_mr_t *rd, char *buf, size_t len)
{
    rdata_name_debug (&rd->newname, buf, len);
}
