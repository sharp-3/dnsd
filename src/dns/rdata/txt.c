#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_txt_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_txt_t *out)
{
    cursor_t start = p->cur;

    // One or more <character-string>s (length octet + octets) filling exactly the len octets:
    // .len describes the strings, so a string running past them is checked here and not only
    // by the record.
    dns_rdata_txt_t rd  = {.data = cursor_ptr (&p->cur), .len = len};
    size_t          end = cursor_bytes (&p->cur) + len;
    dns_error_t     err = len == 0 ? DNS_ERR_BAD_RDATA : DNS_OK;
    while (!cursor_is_overflow (&p->cur) && cursor_bytes (&p->cur) < end)
        cursor_add_bytes (&p->cur, take_bits (&p->cur, 8));
    if (dns_is_ok (err) && !cursor_is_overflow (&p->cur) && cursor_bytes (&p->cur) != end)
        err = DNS_ERR_BAD_RDATA;
    err = rdata_end (p, &start, err, DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

dns_error_t
dns_rdata_txt_to_bytes (dns_cursor_t *p, const dns_rdata_txt_t *rd)
{
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->data, rd->len);
    return rdata_end (p, &start, DNS_OK, DNS_ERR_NO_SPACE);
}

// No domain names: written as by dns_rdata_txt_to_bytes.
dns_error_t
dns_rdata_txt_to_bytes_with_compress (dns_cursor_t *p, const dns_rdata_txt_t *rd)
{
    return dns_rdata_txt_to_bytes (p, rd);
}

// No domain names: nothing to expand.
dns_error_t
dns_rdata_txt_expand (const dns_cursor_t *p, const dns_rdata_txt_t *rdata, dns_rdata_txt_t *out)
{
    (void)p;
    *out = *rdata;
    return DNS_OK;
}

size_t
dns_rdata_txt_length (const dns_rdata_txt_t *rd)
{
    return rd->len;
}

// Appends c to buf (len octets) if it still fits with the NUL; *n counts the octets in buf.
static void
put (char *buf, size_t len, size_t *n, char c)
{
    if (*n + 1 < len) buf[(*n)++] = c;
}

// Each <character-string> quoted, separated by spaces; '"' and '\\' are escaped as \X and
// other non-printable octets as \DDD.
void
rdata_txt_display (const dns_rdata_txt_t *rd, char *buf, size_t len)
{
    const uint8_t *d = rd->data;
    size_t         n = 0;
    for (size_t pos = 0; pos < rd->len; pos += 1 + d[pos])
    {
        if (pos) put (buf, len, &n, ' ');
        put (buf, len, &n, '"');
        for (size_t i = pos + 1; i <= pos + d[pos]; i++)
        {
            uint8_t c = d[i];
            if (c == '"' || c == '\\')
            {
                put (buf, len, &n, '\\');
                put (buf, len, &n, (char)c);
            }
            else if (c < 0x20 || c > 0x7e)
            {
                put (buf, len, &n, '\\');
                put (buf, len, &n, (char)('0' + c / 100));
                put (buf, len, &n, (char)('0' + c / 10 % 10));
                put (buf, len, &n, (char)('0' + c % 10));
            }
            else put (buf, len, &n, (char)c);
        }
        put (buf, len, &n, '"');
    }
    buf[n] = '\0';
}
