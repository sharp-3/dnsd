#include <stdio.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_mx_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_mx_t *out)
{
    cursor_t start = p->cur;

    dns_rdata_mx_t rd;
    rd.preference = take_bits (&p->cur, 16);
    (void)len; // checked against RDLENGTH by the record
    dns_error_t err =
        rdata_end (p, &start, dns_name_from_bytes (p, &rd.exchange), DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_mx_to_bytes (dns_cursor_t *p, const dns_rdata_mx_t *rd, bool compress)
{
    cursor_t start = p->cur;
    emit_bits (&p->cur, 16, rd->preference);
    return rdata_end (p, &start, dns_name_to_bytes (p, &rd->exchange, compress), DNS_ERR_NO_SPACE);
}

size_t
dns_rdata_mx_length (const dns_rdata_mx_t *rd)
{
    return 2 + rd->exchange.len;
}

void
rdata_mx_debug (const dns_rdata_mx_t *rd, char *buf, size_t len)
{
    int n = snprintf (buf, len, "%u ", (unsigned)rd->preference);
    if (n < 0 || len <= (size_t)n) return;
    dns_name_debug_r (&rd->exchange, buf + n, len - n);
}
