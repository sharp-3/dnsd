#include "common.h"

dns_error_t
dns_rdata_mr_from_wire (dns_cursor_t *p, size_t len, dns_rdata_mr_t *out)
{
    return rdata_name_from_wire (p, len, &out->newname);
}

dns_error_t
dns_rdata_mr_to_wire (dns_cursor_t *p, const dns_rdata_mr_t *rd, bool compress)
{
    return rdata_name_to_wire (p, &rd->newname, compress);
}

void
rdata_mr_debug (const dns_rdata_mr_t *self, GString *gs)
{
    rdata_name_debug (&self->newname, gs);
}
