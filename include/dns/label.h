#ifndef DNSD_DNS_LABEL_H
#define DNSD_DNS_LABEL_H

#include <stddef.h>
#include <stdint.h>

#include <glib.h>

#include "dns/error.h"

#define DNS_LABEL_MAX 63
#define DNS_LABEL_POINTER_SIZE 2
#define DNS_LABEL_POINTER_MAX 0x3FFF

typedef enum : uint8_t
{
    DNS_LABEL_TYPE_NORMAL   = 0b00, // length octet (0..63), then that many octets
    DNS_LABEL_TYPE_EXTENDED = 0b01, // reserved (RFC 6891)
    DNS_LABEL_TYPE_UNUSED   = 0b10, // reserved
    DNS_LABEL_TYPE_POINTER  = 0b11, // compression pointer to an earlier label
} dns_label_type_t;

// label (wire format)
dns_label_type_t
dns_label_type (const uint8_t *label);
size_t
dns_label_size (const uint8_t *label);
size_t
dns_label_pointer_target (const uint8_t *label);
void
dns_label_pointer_write (uint8_t *ptr, size_t target);
bool
dns_label_equal (const uint8_t *a, const uint8_t *b);

// label <--> text
dns_error_t
dns_label_from_string (uint8_t *self, const char **str);
dns_error_t
dns_label_to_string (const uint8_t *self, GString *gs);

typedef struct
{
    const uint8_t *buf;
    size_t         len;   // octets in buf
    size_t         pos;   // offset of the next label
    const uint8_t *label; // current label (valid after dns_label_iter_next returned true)
    size_t         off;   // offset of label in buf
    bool           end;   // the name has ended (root label or pointer yielded)
    dns_error_t    err;   // DNS_OK, or why the walk stopped before the name ended:
                          // DNS_ERR_NAME_TRUNCATED (buf ends within a label) or
                          // DNS_ERR_NAME_RESERVED_LABEL (label type 0b01 / 0b10)
} dns_label_iter_t;

// label iteration
void
dns_label_iter_init (dns_label_iter_t *it, const uint8_t *buf, size_t len, size_t pos);
bool
dns_label_iter_next (dns_label_iter_t *it);

#endif
