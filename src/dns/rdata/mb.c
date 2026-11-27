#include "common.h"

dns_error_t
dns_rdata_mb_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_mb_t *out)
{
    return rdata_name_from_bytes (p, len, &out->madname);
}

dns_error_t
dns_rdata_mb_to_bytes (dns_cursor_t *p, const dns_rdata_mb_t *rd, bool compress)
{
    return rdata_name_to_bytes (p, &rd->madname, compress);
}

size_t
dns_rdata_mb_length (const dns_rdata_mb_t *rd)
{
    return rd->madname.len;
}

void
rdata_mb_debug (const dns_rdata_mb_t *rd, char *buf, size_t len)
{
    rdata_name_debug (&rd->madname, buf, len);
}
