#ifndef DNSD_DNS_PARSER_H
#define DNSD_DNS_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include "dns/label.h"
#include "packet/cursor.h"

typedef struct
{
    cursor_t cur; // the message and the read / write position in it
    uint8_t
        label_bitmap[(DNS_LABEL_POINTER_MAX + 1) / 8]; // offsets where a label or pointer starts
} dns_parser_t;

// Starts at offset 0 of pkt.
void
dns_parser_init (dns_parser_t *p, uint8_t *pkt, size_t len);
void
dns_parser_mark_label (dns_parser_t *p, size_t nbytes_off);
void
dns_parser_clear_labels (dns_parser_t *p, size_t from);
int
dns_parser_test_label (const dns_parser_t *p, size_t nbytes_off);

#endif
