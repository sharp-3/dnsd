#include <string.h>

#include "dns/parser.h"

void
dns_parser_init (dns_parser_t *p, uint8_t *pkt, size_t len)
{
    cursor_init (&p->cur, pkt, len);
    memset (p->label_bitmap, 0, sizeof p->label_bitmap);
}

void
dns_parser_mark_label (dns_parser_t *p, size_t nbytes_off)
{
    if (nbytes_off <= DNS_LABEL_POINTER_MAX)
        p->label_bitmap[nbytes_off >> 3] |= 1 << (nbytes_off & 0b111);
}

// Forget every label start at or after from (not yet read / written).
void
dns_parser_clear_labels (dns_parser_t *p, size_t from)
{
    if (from > DNS_LABEL_POINTER_MAX) return;

    size_t byte = from >> 3;
    p->label_bitmap[byte] &= (1 << (from & 0b111)) - 1;
    memset (p->label_bitmap + byte + 1, 0, sizeof p->label_bitmap - byte - 1);
}

int
dns_parser_test_label (const dns_parser_t *p, size_t nbytes_off)
{
    if (nbytes_off <= DNS_LABEL_POINTER_MAX)
        return (p->label_bitmap[nbytes_off >> 3] & (1 << (nbytes_off & 0b111))) != 0;
    return 0;
}
