#include "common.h"

dns_error_t
dns_rdata_mb_from_wire (dns_cursor_t *p, size_t len, dns_rdata_mb_t *out)
{
    return rdata_name_from_wire (p, len, &out->madname);
}

dns_error_t
dns_rdata_mb_to_wire (dns_cursor_t *p, const dns_rdata_mb_t *rd, bool compress)
{
    return rdata_name_to_wire (p, &rd->madname, compress);
}

size_t
dns_rdata_mb_length (const dns_rdata_mb_t *rd)
{
    return rd->madname.len;
}

void
rdata_mb_debug (const dns_rdata_mb_t *self, GString *gs)
{
    rdata_name_debug (&self->madname, gs);
}
