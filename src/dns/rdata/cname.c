#include "common.h"

dns_error_t
dns_rdata_cname_from_wire (dns_cursor_t *p, size_t len, dns_rdata_cname_t *out)
{
    return rdata_name_from_wire (p, len, &out->cname);
}

dns_error_t
dns_rdata_cname_to_wire (dns_cursor_t *p, const dns_rdata_cname_t *rd, bool compress)
{
    return rdata_name_to_wire (p, &rd->cname, compress);
}

size_t
dns_rdata_cname_length (const dns_rdata_cname_t *rd)
{
    return rd->cname.len;
}

void
rdata_cname_debug (const dns_rdata_cname_t *self, GString *gs)
{
    rdata_name_debug (&self->cname, gs);
}
