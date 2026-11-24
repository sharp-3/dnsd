#include "common.h"
#include "packet/emit.h"

dns_error_t
dns_rdata_unknown_from_bytes (dns_parser_t *p, size_t len, dns_rdata_unknown_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_unknown_t rd;
    rd.data = cursor_ptr (&p->cur);
    rd.len  = len;
    cursor_add_bytes (&p->cur, len);
    err = rdata_end (p, &start, DNS_OK);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_unknown_to_bytes (dns_parser_t *p, const dns_rdata_unknown_t *rd)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->data, rd->len);
    return rdata_put_end (p, &start);
}

size_t
rdata_unknown_length (const dns_rdata_unknown_t *rd)
{
    return rd->len;
}

void
rdata_unknown_display (const dns_rdata_unknown_t *rd, char *buf, size_t len, size_t *out)
{
    rdata_appendf (buf, len, out, "\\# %zu", rd->len);
    if (rd->len) rdata_appendf (buf, len, out, " ");
    for (size_t i = 0; i < rd->len; i++)
        rdata_appendf (buf, len, out, "%02x", rd->data[i]);
}
