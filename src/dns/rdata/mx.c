#include "common.h"
#include "packet/emit.h"
#include "packet/take.h"

dns_error_t
dns_rdata_mx_from_bytes (dns_parser_t *p, size_t len, dns_rdata_mx_t *out)
{
    cursor_t    start;
    dns_error_t err = rdata_begin (p, len, &start);
    if (err != DNS_OK) return err;

    dns_rdata_mx_t rd;
    rd.preference = take_bits (&p->cur, 16);
    err           = rdata_end (p, &start, dns_name_from_bytes (p, &rd.exchange));
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_mx_to_bytes (dns_parser_t *p, const dns_rdata_mx_t *rd)
{
    cursor_t start = p->cur;
    emit_bits (&p->cur, 16, rd->preference);
    emit_bytes (&p->cur, rd->exchange.ptr, rd->exchange.len);
    return rdata_put_end (p, &start);
}

size_t
rdata_mx_length (const dns_rdata_mx_t *rd)
{
    return 2 + rd->exchange.len;
}

void
rdata_mx_display (const dns_rdata_mx_t *rd, char *buf, size_t len, size_t *out)
{
    rdata_appendf (
        buf, len, out, "%u %s", (unsigned)rd->preference, dns_name_debug (&rd->exchange));
}
