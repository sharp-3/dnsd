#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_txt_from_wire (dns_cursor_t *p, size_t len, dns_rdata_txt_t *out)
{
    cursor_t start = p->cur;

    // One or more <character-string>s (length octet + octets) filling exactly the len octets:
    // .len describes the strings, so a string running past them is checked here and not only
    // by the record.
    dns_rdata_txt_t rd  = {.data = cursor_ptr (&p->cur), .len = len};
    size_t          end = cursor_bytes (&p->cur) + len;
    dns_error_t     err = 0 == len ? DNS_ERR_BAD_RDATA : DNS_OK;
    while (!cursor_is_overflow (&p->cur) && cursor_bytes (&p->cur) < end)
        cursor_add (&p->cur, take_bits (&p->cur, 8), 0);
    if (dns_is_ok (err) && !cursor_is_overflow (&p->cur) && cursor_bytes (&p->cur) != end)
        err = DNS_ERR_BAD_RDATA;
    err = rdata_end (p, &start, err, DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

// No domain names: compress has no effect.
dns_error_t
dns_rdata_txt_to_wire (dns_cursor_t *p, const dns_rdata_txt_t *rd, bool compress)
{
    (void)compress;
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->data, rd->len);
    return rdata_end (p, &start, DNS_OK, DNS_ERR_NO_SPACE);
}

size_t
dns_rdata_txt_length (const dns_rdata_txt_t *rd)
{
    return rd->len;
}

// Each <character-string> quoted, separated by spaces; '"' and '\\' are escaped as \X and
// other non-printable octets as \DDD.
void
rdata_txt_debug (const dns_rdata_txt_t *self, GString *gs)
{
    const uint8_t *d = self->data;
    for (size_t pos = 0; pos < self->len; pos += 1 + d[pos])
    {
        if (pos) g_string_append_c (gs, ' ');
        g_string_append_c (gs, '"');
        for (size_t i = pos + 1; i <= pos + d[pos]; i++)
        {
            uint8_t c = d[i];
            if ('"' == c || '\\' == c) g_string_append_printf (gs, "\\%c", c);
            else if (c < 0x20 || 0x7e < c) g_string_append_printf (gs, "\\%03u", c);
            else g_string_append_c (gs, (char)c);
        }
        g_string_append_c (gs, '"');
    }
}
