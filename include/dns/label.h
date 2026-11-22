#ifndef DNSD_DNS_LABEL_H
#define DNSD_DNS_LABEL_H

#include <stddef.h>
#include <stdint.h>

#include "dns/error.h"

#define DNS_LABEL_MAX 63
#define DNS_LABEL_ESCAPE_SIZE (sizeof "\\DDD" - 1)
#define DNS_LABEL_POINTER_SIZE 2
#define DNS_LABEL_POINTER_MAX 0x3FFF

typedef enum : uint8_t
{
    DNS_LABEL_TYPE_NORMAL   = 0b00, // length octet (0..63), then that many octets
    DNS_LABEL_TYPE_EXTENDED = 0b01, // reserved (RFC 6891)
    DNS_LABEL_TYPE_UNUSED   = 0b10, // reserved
    DNS_LABEL_TYPE_POINTER  = 0b11, // compression pointer to an earlier label
} dns_label_type_t;

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
dns_error_t
dns_label_to_string (const uint8_t *label, char *buf, size_t len, size_t *out);
dns_error_t
dns_label_from_string (const char **str, uint8_t *label, size_t len);

#endif
