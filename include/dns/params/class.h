#ifndef DNSD_DNS_PARAMS_CLASS_H
#define DNSD_DNS_PARAMS_CLASS_H

#include <stddef.h>
#include <stdint.h>

#include "dns/error.h"

#define DNS_CLASS_SIZE 2 // octets in wire format
#define DNS_CLASS_DISPLAY_SIZE sizeof "CLASS65535"

typedef enum : uint16_t
{
    DNS_CLASS_IN   = 1,   // Internet
    DNS_CLASS_CH   = 3,   // Chaos
    DNS_CLASS_HS   = 4,   // Hesiod
    DNS_CLASS_NONE = 254, // none (RFC 2136)
    DNS_CLASS_ANY  = 255, // any class (QCLASS only)
} dns_class_t;

// category (RFC 6895 3.2)
bool
dns_class_is_data (dns_class_t class);
bool
dns_class_is_qonly_or_meta (dns_class_t class);
bool
dns_class_is_reserved (dns_class_t class);

// dns_class_t <-- char * (string)
dns_error_t
dns_class_from_string (const char *str, dns_class_t *out);

// display
const char *
dns_class_display_r (dns_class_t value, char *buf, size_t len);
#define dns_class_display(value)                                                                   \
    dns_class_display_r ((value), (char[DNS_CLASS_DISPLAY_SIZE]){}, DNS_CLASS_DISPLAY_SIZE)

#endif
