#include <string.h>

#include "dns/cursor.h"

void
dns_cursor_init (dns_cursor_t *p, uint8_t *pkt, size_t len)
{
    cursor_init (&p->cur, pkt, len);
    memset (p->label_bitmap, 0, sizeof p->label_bitmap);
}

void
dns_cursor_mark_label (dns_cursor_t *p, size_t nbytes_off)
{
    if (nbytes_off <= DNS_LABEL_POINTER_MAX)
        p->label_bitmap[nbytes_off >> 3] |= 1 << (nbytes_off & 0b111);
}

void
dns_cursor_clear_labels (dns_cursor_t *p, size_t from)
{
    if (DNS_LABEL_POINTER_MAX < from) return;

    size_t byte = from >> 3;
    p->label_bitmap[byte] &= (1 << (from & 0b111)) - 1;
    memset (p->label_bitmap + byte + 1, 0, sizeof p->label_bitmap - byte - 1);
}

void
dns_cursor_rewind (dns_cursor_t *p, const cursor_t *pos)
{
    p->cur = *pos;
    dns_cursor_clear_labels (p, cursor_bytes (pos));
}

dns_error_t
dns_cursor_rewind_return_error (cursor_t pos, dns_cursor_t *p, dns_error_t err)
{
    dns_cursor_rewind (p, &pos);
    return err;
}

bool
dns_cursor_test_label (const dns_cursor_t *p, size_t nbytes_off)
{
    if (nbytes_off <= DNS_LABEL_POINTER_MAX)
        return 0 != (p->label_bitmap[nbytes_off >> 3] & (1 << (nbytes_off & 0b111)));
    return false;
}
