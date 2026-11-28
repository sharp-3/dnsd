#include "common.h"
#include "packet/cursor.h"

dns_error_t
rdata_end (dns_cursor_t *p, const cursor_t *start, dns_error_t err, dns_error_t overflow_err)
{
    if (dns_is_ok (err) && cursor_is_overflow (&p->cur)) err = overflow_err;
    if (dns_is_ok (err)) return err;
    return dns_cursor_rewind_return_error (*start, p, err);
}

dns_error_t
rdata_name_from_wire (dns_cursor_t *p, size_t len, dns_name_ref_t *out)
{
    (void)len; // checked against RDLENGTH by the record
    return dns_name_from_wire (p, out);
}

dns_error_t
rdata_name_to_wire (dns_cursor_t *p, const dns_name_ref_t *name, bool compress)
{
    cursor_t start = p->cur;
    return rdata_end (p, &start, dns_name_to_wire (p, name, compress), DNS_ERR_NO_SPACE);
}

void
rdata_name_debug (const dns_name_ref_t *self, GString *gs)
{
    dns_name_debug (self, gs);
}
