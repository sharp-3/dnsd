#include "common.h"

static dns_error_t
rdata_ptr_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_ptr_t *out)
{
    return rdata_name_from_bytes (p, len, &out->ptrdname);
}

bool
dns_rdata_ptr_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_ptr_t *out)
{
    if (p->err != DNS_OK) return false;
    dns_error_t warn = p->warn;
    return dns_cursor_finish (p, warn, rdata_ptr_from_bytes (p, len, out));
}

static dns_error_t
rdata_ptr_to_bytes (dns_cursor_t *p, const dns_rdata_ptr_t *rd)
{
    return rdata_name_to_bytes (p, &rd->ptrdname);
}

bool
dns_rdata_ptr_to_bytes (dns_cursor_t *p, const dns_rdata_ptr_t *rd)
{
    if (p->err != DNS_OK) return false;
    dns_error_t warn = p->warn;
    return dns_cursor_finish (p, warn, rdata_ptr_to_bytes (p, rd));
}

size_t
rdata_ptr_length (const dns_rdata_ptr_t *rd)
{
    return rd->ptrdname.len;
}

void
rdata_ptr_display (const dns_rdata_ptr_t *rd, char *buf, size_t len)
{
    rdata_name_display (&rd->ptrdname, buf, len);
}
