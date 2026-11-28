#include "common.h"

dns_error_t
dns_rdata_ns_from_wire (dns_cursor_t *p, size_t len, dns_rdata_ns_t *out)
{
    return rdata_name_from_wire (p, len, &out->nsdname);
}

dns_error_t
dns_rdata_ns_to_wire (dns_cursor_t *p, const dns_rdata_ns_t *rd, bool compress)
{
    return rdata_name_to_wire (p, &rd->nsdname, compress);
}

size_t
dns_rdata_ns_length (const dns_rdata_ns_t *rd)
{
    return rd->nsdname.len;
}

void
rdata_ns_debug (const dns_rdata_ns_t *self, GString *gs)
{
    rdata_name_debug (&self->nsdname, gs);
}
