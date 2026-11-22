#ifndef DNSD_DNS_CLASS_H
#define DNSD_DNS_CLASS_H

#include <stddef.h>
#include <stdint.h>

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

const char *
dns_class_display_r (dns_class_t value, char *buf, size_t len);
#define dns_class_display(value)                                                                   \
    dns_class_display_r ((value), (char[DNS_CLASS_DISPLAY_SIZE]){}, DNS_CLASS_DISPLAY_SIZE)

#endif
