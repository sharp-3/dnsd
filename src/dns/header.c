#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/header.h"
#include "packet/cursor.h"

dns_error_t
dns_header_from_wire (dns_cursor_t *p, dns_header_t *out)
{
    cursor_t     start = p->cur;
    dns_header_t h;
    h.id      = take_bits (&p->cur, 16);
    h.qr      = take_bits (&p->cur, 1);
    h.opcode  = take_bits (&p->cur, 4);
    h.aa      = take_bits (&p->cur, 1);
    h.tc      = take_bits (&p->cur, 1);
    h.rd      = take_bits (&p->cur, 1);
    h.ra      = take_bits (&p->cur, 1);
    h.z       = take_bits (&p->cur, 1);
    h.ad      = take_bits (&p->cur, 1);
    h.cd      = take_bits (&p->cur, 1);
    h.rcode   = take_bits (&p->cur, 4);
    h.qdcount = take_bits (&p->cur, 16);
    h.ancount = take_bits (&p->cur, 16);
    h.nscount = take_bits (&p->cur, 16);
    h.arcount = take_bits (&p->cur, 16);
    if (cursor_is_overflow (&p->cur))
        return dns_cursor_rewind_return_error (start, p, DNS_ERR_TRUNCATED);

    *out = h;
    return DNS_OK;
}

dns_error_t
dns_header_to_wire (dns_cursor_t *p, const dns_header_t *hdr)
{
    cursor_t start = p->cur;
    emit_bits (&p->cur, 16, hdr->id);
    emit_bits (&p->cur, 1, hdr->qr);
    emit_bits (&p->cur, 4, hdr->opcode);
    emit_bits (&p->cur, 1, hdr->aa);
    emit_bits (&p->cur, 1, hdr->tc);
    emit_bits (&p->cur, 1, hdr->rd);
    emit_bits (&p->cur, 1, hdr->ra);
    emit_bits (&p->cur, 1, hdr->z);
    emit_bits (&p->cur, 1, hdr->ad);
    emit_bits (&p->cur, 1, hdr->cd);
    emit_bits (&p->cur, 4, hdr->rcode);
    emit_bits (&p->cur, 16, hdr->qdcount);
    emit_bits (&p->cur, 16, hdr->ancount);
    emit_bits (&p->cur, 16, hdr->nscount);
    emit_bits (&p->cur, 16, hdr->arcount);
    if (cursor_is_overflow (&p->cur))
        return dns_cursor_rewind_return_error (start, p, DNS_ERR_NO_SPACE);
    return DNS_OK;
}

GString *
dns_header_debug (const dns_header_t *self, GString *gs)
{
    g_string_append_printf (gs, "id=0x%04X", self->id);
    g_string_append (gs, self->qr ? " qr" : "");
    g_string_append (gs, self->aa ? " aa" : "");
    g_string_append (gs, self->tc ? " tc" : "");
    g_string_append (gs, self->rd ? " rd" : "");
    g_string_append (gs, self->ra ? " ra" : "");
    g_string_append (gs, self->z ? " z" : "");
    g_string_append (gs, self->ad ? " ad" : "");
    g_string_append (gs, self->cd ? " cd" : "");
    g_string_append (gs, " opcode=");
    dns_opcode_to_string (self->opcode, gs);
    g_string_append (gs, " rcode=");
    dns_rcode_to_string (self->rcode, gs);
    g_string_append_printf (gs, " qdcount=%u", self->qdcount);
    g_string_append_printf (gs, " ancount=%u", self->ancount);
    g_string_append_printf (gs, " nscount=%u", self->nscount);
    g_string_append_printf (gs, " arcount=%u", self->arcount);
    return gs;
}
