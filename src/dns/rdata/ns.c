#include "common.h"

dns_error_t
dns_rdata_ns_from_bytes (dns_parser_t *p, size_t len, dns_rdata_ns_t *out)
{
    return rdata_name_from_bytes (p, len, &out->nsdname);
}

dns_error_t
dns_rdata_ns_to_bytes (dns_parser_t *p, const dns_rdata_ns_t *rd)
{
    return rdata_name_to_bytes (p, &rd->nsdname);
}

size_t
rdata_ns_length (const dns_rdata_ns_t *rd)
{
    return rd->nsdname.len;
}

void
rdata_ns_display (const dns_rdata_ns_t *rd, char *buf, size_t len)
{
    rdata_name_display (&rd->nsdname, buf, len);
}
