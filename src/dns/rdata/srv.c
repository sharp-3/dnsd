#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_srv_from_wire (dns_cursor_t *p, size_t len, dns_rdata_srv_t *out)
{
    cursor_t start = p->cur;

    dns_rdata_srv_t rd;
    rd.priority = take_bits (&p->cur, 16);
    rd.weight   = take_bits (&p->cur, 16);
    rd.port     = take_bits (&p->cur, 16);
    (void)len; // checked against RDLENGTH by the record
    dns_error_t err = rdata_end (p, &start, dns_name_from_wire (p, &rd.target), DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_srv_to_wire (dns_cursor_t *p, const dns_rdata_srv_t *rd, bool compress)
{
    (void)compress;
    cursor_t start = p->cur;
    emit_bits (&p->cur, 16, rd->priority);
    emit_bits (&p->cur, 16, rd->weight);
    emit_bits (&p->cur, 16, rd->port);
    return rdata_end (p, &start, dns_name_to_wire (p, &rd->target, false), DNS_ERR_NO_SPACE);
}

void
rdata_srv_debug (const dns_rdata_srv_t *self, GString *gs)
{
    g_string_append_printf (
        gs, "%u %u %u ", (unsigned)self->priority, (unsigned)self->weight, (unsigned)self->port);
    dns_name_debug (&self->target, gs);
}
