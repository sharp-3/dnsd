#include "common.h"

static dns_error_t
rdata_cname_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_cname_t *out)
{
    return rdata_name_from_bytes (p, len, &out->cname);
}

bool
dns_rdata_cname_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_cname_t *out)
{
    if (p->err != DNS_OK) return false;
    dns_error_t warn = p->warn;
    return dns_cursor_finish (p, warn, rdata_cname_from_bytes (p, len, out));
}

static dns_error_t
rdata_cname_to_bytes (dns_cursor_t *p, const dns_rdata_cname_t *rd)
{
    return rdata_name_to_bytes (p, &rd->cname);
}

bool
dns_rdata_cname_to_bytes (dns_cursor_t *p, const dns_rdata_cname_t *rd)
{
    if (p->err != DNS_OK) return false;
    dns_error_t warn = p->warn;
    return dns_cursor_finish (p, warn, rdata_cname_to_bytes (p, rd));
}

size_t
rdata_cname_length (const dns_rdata_cname_t *rd)
{
    return rd->cname.len;
}

void
rdata_cname_display (const dns_rdata_cname_t *rd, char *buf, size_t len)
{
    rdata_name_display (&rd->cname, buf, len);
}
