#include "common.h"

dns_error_t
dns_rdata_mg_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_mg_t *out)
{
    return rdata_name_from_bytes (p, len, &out->mgmname);
}

dns_error_t
dns_rdata_mg_to_bytes (dns_cursor_t *p, const dns_rdata_mg_t *rd, bool compress)
{
    return rdata_name_to_bytes (p, &rd->mgmname, compress);
}

size_t
dns_rdata_mg_length (const dns_rdata_mg_t *rd)
{
    return rd->mgmname.len;
}

void
rdata_mg_debug (const dns_rdata_mg_t *rd, char *buf, size_t len)
{
    rdata_name_debug (&rd->mgmname, buf, len);
}
