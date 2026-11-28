#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_a_from_wire (dns_cursor_t *p, size_t len, dns_rdata_a_t *out)
{
    cursor_t start = p->cur;

    dns_rdata_a_t rd;
    take_bytes (&p->cur, rd.addr, sizeof rd.addr);
    (void)len; // checked against RDLENGTH by the record
    dns_error_t err = rdata_end (p, &start, DNS_OK, DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_a_to_wire (dns_cursor_t *p, const dns_rdata_a_t *rd, bool compress)
{
    (void)compress;
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->addr, sizeof rd->addr);
    return rdata_end (p, &start, DNS_OK, DNS_ERR_NO_SPACE);
}

void
rdata_a_debug (const dns_rdata_a_t *self, GString *gs)
{
    const uint8_t *a = self->addr;
    g_string_append_printf (gs, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}
