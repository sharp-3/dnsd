#include "common.h"

dns_error_t
dns_rdata_ptr_from_wire (dns_cursor_t *p, size_t len, dns_rdata_ptr_t *out)
{
    return rdata_name_from_wire (p, len, &out->ptrdname);
}

dns_error_t
dns_rdata_ptr_to_wire (dns_cursor_t *p, const dns_rdata_ptr_t *rd, bool compress)
{
    return rdata_name_to_wire (p, &rd->ptrdname, compress);
}

void
rdata_ptr_debug (const dns_rdata_ptr_t *self, GString *gs)
{
    rdata_name_debug (&self->ptrdname, gs);
}
