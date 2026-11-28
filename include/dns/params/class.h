#ifndef DNSD_DNS_PARAMS_CLASS_H
#define DNSD_DNS_PARAMS_CLASS_H

#include <stddef.h>
#include <stdint.h>

#include <glib.h>

#include "dns/error.h"

#define DNS_CLASS_SIZE 2 // octets in wire format

typedef enum : uint16_t
{
    DNS_CLASS_IN   = 1,   // Internet
    DNS_CLASS_CH   = 3,   // Chaos
    DNS_CLASS_HS   = 4,   // Hesiod
    DNS_CLASS_NONE = 254, // none (RFC 2136)
    DNS_CLASS_ANY  = 255, // any class (QCLASS only)
} dns_class_t;

// category (RFC 6895 3.2): the ranges of each, in order
#define DNS_CLASS_RESERVED_LOW 0x0000
#define DNS_CLASS_DATA_LOW_MIN 0x0001
#define DNS_CLASS_DATA_LOW_MAX 0x007F
#define DNS_CLASS_QONLY_OR_META_LOW_MIN 0x0080
#define DNS_CLASS_QONLY_OR_META_LOW_MAX 0x00FF
#define DNS_CLASS_DATA_MID_MIN 0x0100
#define DNS_CLASS_DATA_MID_MAX 0xDFFF
#define DNS_CLASS_QONLY_OR_META_HIGH_MIN 0xE000
#define DNS_CLASS_QONLY_OR_META_HIGH_MAX 0xFEFF
#define DNS_CLASS_DATA_HIGH_MIN 0xFF00
#define DNS_CLASS_DATA_HIGH_MAX 0xFFFE
#define DNS_CLASS_RESERVED_HIGH 0xFFFF

bool
dns_class_is_data (dns_class_t class);
bool
dns_class_is_qonly_or_meta (dns_class_t class);
bool
dns_class_is_reserved (dns_class_t class);

// dns_class_t <--> text
dns_error_t
dns_class_from_string (dns_class_t *self, const char *str);
dns_error_t
dns_class_to_string (dns_class_t self, GString *gs);

#endif
