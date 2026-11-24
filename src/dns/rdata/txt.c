#include "common.h"
#include "packet/emit.h"
#include "packet/take.h"

dns_error_t
dns_rdata_txt_from_bytes (dns_parser_t *p, size_t len, dns_rdata_txt_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_txt_t rd;
    // One or more <character-string>s (length octet + octets); a length running past the
    // RDATA overflows.
    rd.data = cursor_ptr (&p->cur);
    rd.len  = len;
    if (len == 0) err = DNS_ERR_BAD_RDATA;
    while (!cursor_is_overflow (&p->cur) && cursor_bytes (&p->cur) < p->cur.len)
        cursor_add_bytes (&p->cur, take_bits (&p->cur, 8));
    err = rdata_end (p, &start, err);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_txt_to_bytes (dns_parser_t *p, const dns_rdata_txt_t *rd)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->data, rd->len);
    return rdata_put_end (p, &start);
}

size_t
rdata_txt_length (const dns_rdata_txt_t *rd)
{
    return rd->len;
}

void
rdata_txt_display (const dns_rdata_txt_t *rd, char *buf, size_t len, size_t *out)
{
    const uint8_t *d = rd->data;
    for (size_t pos = 0; pos < rd->len; pos += 1 + d[pos])
    {
        if (pos) rdata_appendf (buf, len, out, " ");
        rdata_append_string (buf, len, out, d + pos + 1, d[pos]);
    }
}
