#ifndef DNSD_DNS_CURSOR_H
#define DNSD_DNS_CURSOR_H

#include <stddef.h>
#include <stdint.h>

#include "dns/error.h"
#include "dns/label.h"
#include "packet/cursor.h"

typedef struct
{
    cursor_t    cur;  // the message and the read / write position in it
    dns_error_t err;  // first error met (DNS_OK if none); see dns_cursor_set_error
    dns_error_t warn; // first warning (DNS_OK_*) met by a call that succeeded (DNS_OK if none)
    uint8_t
        label_bitmap[(DNS_LABEL_POINTER_MAX + 1) / 8]; // offsets where a label or pointer starts
} dns_cursor_t;

// Starts at offset 0 of pkt, with no error or warning.
void
dns_cursor_init (dns_cursor_t *p, uint8_t *pkt, size_t len);
// Records err: an error goes to p->err and a warning (DNS_OK_*) to p->warn, each only if none is
// recorded yet, so both keep the first one. Returns whether err is a success (DNS_OK or a
// warning).
bool
dns_cursor_set_error (dns_cursor_t *p, dns_error_t err);

// The functions that read or write through a dns_cursor_t (the *_from_bytes and *_to_bytes ones)
// return whether they succeeded. On failure p->err tells why, and p->cur and their output are
// left as they were. A warning, such as DNS_OK_NAME_TOO_LONG, still counts as success and is
// recorded in p->warn. Once p->err is set they do nothing and return false.
//
// They are built on a body returning dns_error_t:
//
//     if (p->err != DNS_OK) return false;
//     dns_error_t warn = p->warn;
//     return dns_cursor_finish (p, warn, body (p, ...));
//
// Ends such a call that started with p->warn == warn and whose body returned err. On an error,
// err replaces whatever the calls nested in the body recorded in p->err, and p->warn goes back
// to warn. Returns whether err is a success.
bool
dns_cursor_finish (dns_cursor_t *p, dns_error_t warn, dns_error_t err);

void
dns_cursor_mark_label (dns_cursor_t *p, size_t nbytes_off);
void
dns_cursor_clear_labels (dns_cursor_t *p, size_t from);
bool
dns_cursor_test_label (const dns_cursor_t *p, size_t nbytes_off);

#endif
