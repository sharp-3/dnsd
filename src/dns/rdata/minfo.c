#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_minfo_from_wire (dns_cursor_t *p, size_t len, dns_rdata_minfo_t *out)
{
    cursor_t start = p->cur;

    (void)len; // checked against RDLENGTH by the record
    dns_rdata_minfo_t rd;
    dns_error_t       err = dns_name_from_wire (p, &rd.rmailbx);
    if (dns_is_ok (err)) err = dns_merge_soft (err, dns_name_from_wire (p, &rd.emailbx));
    err = rdata_end (p, &start, err, DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

// With compress, EMAILBX may be compressed against RMAILBX too.
dns_error_t
dns_rdata_minfo_to_wire (dns_cursor_t *p, const dns_rdata_minfo_t *rd, bool compress)
{
    cursor_t    start = p->cur;
    dns_error_t err   = dns_name_to_wire (p, &rd->rmailbx, compress);
    if (dns_is_ok (err)) err = dns_merge_soft (err, dns_name_to_wire (p, &rd->emailbx, compress));
    return rdata_end (p, &start, err, DNS_ERR_NO_SPACE);
}

void
rdata_minfo_debug (const dns_rdata_minfo_t *self, GString *gs)
{
    dns_name_debug (&self->rmailbx, gs);
    g_string_append_c (gs, ' ');
    dns_name_debug (&self->emailbx, gs);
}
