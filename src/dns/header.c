#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "dns/cursor.h"
#include "dns/header.h"
#include "packet/cursor.h"

dns_error_t
dns_header_from_bytes (dns_cursor_t *p, dns_header_t *out)
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
    {
        p->cur = start;
        return DNS_ERR_TRUNCATED;
    }

    *out = h;
    return DNS_OK;
}

dns_error_t
dns_header_to_bytes (dns_cursor_t *p, const dns_header_t *hdr)
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
    {
        p->cur = start;
        return DNS_ERR_NO_SPACE;
    }
    return DNS_OK;
}

const char *
dns_header_display_r (const dns_header_t *hdr, char *buf, size_t len)
{
    snprintf (buf,
              len,
              "id=0x%04X%s%s%s%s%s%s%s%s opcode=%s rcode=%s "
              "qdcount=%u ancount=%u nscount=%u arcount=%u",
              hdr->id,
              hdr->qr ? " qr" : "",
              hdr->aa ? " aa" : "",
              hdr->tc ? " tc" : "",
              hdr->rd ? " rd" : "",
              hdr->ra ? " ra" : "",
              hdr->z ? " z" : "",
              hdr->ad ? " ad" : "",
              hdr->cd ? " cd" : "",
              dns_opcode_display (hdr->opcode),
              dns_rcode_display (hdr->rcode),
              hdr->qdcount,
              hdr->ancount,
              hdr->nscount,
              hdr->arcount);
    return buf;
}
