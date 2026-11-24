#include "common.h"

static dns_error_t
rdata_ns_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_ns_t *out)
{
    return rdata_name_from_bytes (p, len, &out->nsdname);
}

bool
dns_rdata_ns_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_ns_t *out)
{
    if (p->err != DNS_OK) return false;
    dns_error_t warn = p->warn;
    return dns_cursor_finish (p, warn, rdata_ns_from_bytes (p, len, out));
}

static dns_error_t
rdata_ns_to_bytes (dns_cursor_t *p, const dns_rdata_ns_t *rd)
{
    return rdata_name_to_bytes (p, &rd->nsdname);
}

bool
dns_rdata_ns_to_bytes (dns_cursor_t *p, const dns_rdata_ns_t *rd)
{
    if (p->err != DNS_OK) return false;
    dns_error_t warn = p->warn;
    return dns_cursor_finish (p, warn, rdata_ns_to_bytes (p, rd));
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
