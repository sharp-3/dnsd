#ifndef DNSD_DNS_CURSOR_H
#define DNSD_DNS_CURSOR_H

#include <stddef.h>
#include <stdint.h>

#include "dns/label.h"
#include "packet/cursor.h"

typedef struct
{
    cursor_t cur; // the message and the read / write position in it
    uint8_t
        label_bitmap[(DNS_LABEL_POINTER_MAX + 1) / 8]; // offsets where a label or pointer starts
} dns_cursor_t;

// Starts at offset 0 of pkt.
void
dns_cursor_init (dns_cursor_t *p, uint8_t *pkt, size_t len);
void
dns_cursor_mark_label (dns_cursor_t *p, size_t nbytes_off);
void
dns_cursor_clear_labels (dns_cursor_t *p, size_t from);
bool
dns_cursor_test_label (const dns_cursor_t *p, size_t nbytes_off);

#endif
