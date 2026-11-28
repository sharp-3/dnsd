#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_unknown_from_wire (dns_cursor_t *p, size_t len, dns_rdata_unknown_t *out)
{
    cursor_t start = p->cur;

    dns_rdata_unknown_t rd;
    rd.data = cursor_ptr (&p->cur);
    rd.len  = len;
    cursor_add (&p->cur, len, 0);
    dns_error_t err = rdata_end (p, &start, DNS_OK, DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

// No domain names: compress has no effect.
dns_error_t
dns_rdata_unknown_to_wire (dns_cursor_t *p, const dns_rdata_unknown_t *rd, bool compress)
{
    (void)compress;
    cursor_t start = p->cur;
    emit_bytes (&p->cur, rd->data, rd->len);
    return rdata_end (p, &start, DNS_OK, DNS_ERR_NO_SPACE);
}

size_t
dns_rdata_unknown_length (const dns_rdata_unknown_t *rd)
{
    return rd->len;
}

void
rdata_unknown_debug (const dns_rdata_unknown_t *self, GString *gs)
{
    g_string_append_printf (gs, "\\# %zu", self->len);
    if (0 < self->len) g_string_append_c (gs, ' ');
    for (size_t i = 0; i < self->len; i++)
        g_string_append_printf (gs, "%02x", self->data[i]);
}
