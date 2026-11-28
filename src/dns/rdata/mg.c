#include "common.h"

dns_error_t
dns_rdata_mg_from_wire (dns_cursor_t *p, size_t len, dns_rdata_mg_t *out)
{
    return rdata_name_from_wire (p, len, &out->mgmname);
}

dns_error_t
dns_rdata_mg_to_wire (dns_cursor_t *p, const dns_rdata_mg_t *rd, bool compress)
{
    return rdata_name_to_wire (p, &rd->mgmname, compress);
}

void
rdata_mg_debug (const dns_rdata_mg_t *self, GString *gs)
{
    rdata_name_debug (&self->mgmname, gs);
}
