#include <string.h>

#include "dns/cursor.h"

void
dns_cursor_init (dns_cursor_t *p, uint8_t *pkt, size_t len)
{
    cursor_init (&p->cur, pkt, len);
    p->err  = DNS_OK;
    p->warn = DNS_OK;
    memset (p->label_bitmap, 0, sizeof p->label_bitmap);
}

bool
dns_cursor_set_error (dns_cursor_t *p, dns_error_t err)
{
    if (err == DNS_OK) return true;
    dns_error_t *slot = dns_is_ok (err) ? &p->warn : &p->err;
    if (*slot == DNS_OK) *slot = err;
    return dns_is_ok (err);
}

bool
dns_cursor_finish (dns_cursor_t *p, dns_error_t warn, dns_error_t err)
{
    if (!dns_is_ok (err))
    {
        p->err  = DNS_OK;
        p->warn = warn;
    }
    return dns_cursor_set_error (p, err);
}

void
dns_cursor_mark_label (dns_cursor_t *p, size_t nbytes_off)
{
    if (nbytes_off <= DNS_LABEL_POINTER_MAX)
        p->label_bitmap[nbytes_off >> 3] |= 1 << (nbytes_off & 0b111);
}

// Forget every label start at or after from (not yet read / written).
void
dns_cursor_clear_labels (dns_cursor_t *p, size_t from)
{
    if (from > DNS_LABEL_POINTER_MAX) return;

    size_t byte = from >> 3;
    p->label_bitmap[byte] &= (1 << (from & 0b111)) - 1;
    memset (p->label_bitmap + byte + 1, 0, sizeof p->label_bitmap - byte - 1);
}

bool
dns_cursor_test_label (const dns_cursor_t *p, size_t nbytes_off)
{
    if (nbytes_off <= DNS_LABEL_POINTER_MAX)
        return (p->label_bitmap[nbytes_off >> 3] & (1 << (nbytes_off & 0b111))) != 0;
    return false;
}
