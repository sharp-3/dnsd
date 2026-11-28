#include "common.h"

dns_error_t
dns_rdata_dname_from_wire (dns_cursor_t *p, size_t len, dns_rdata_dname_t *out)
{
    return rdata_name_from_wire (p, len, &out->target);
}

dns_error_t
dns_rdata_dname_to_wire (dns_cursor_t *p, const dns_rdata_dname_t *rd, bool compress)
{
    // The target must not be compressed (RFC 6672): written uncompressed whatever compress is;
    // dns_name_to_wire rejects a compressed one.
    (void)compress;
    return rdata_name_to_wire (p, &rd->target, false);
}

void
rdata_dname_debug (const dns_rdata_dname_t *self, GString *gs)
{
    rdata_name_debug (&self->target, gs);
}
