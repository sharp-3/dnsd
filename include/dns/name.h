#ifndef DNSD_DNS_NAME_H
#define DNSD_DNS_NAME_H

#include <stddef.h>
#include <stdint.h>

#include <glib.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/label.h"

#define DNS_NAME_MAX 255

typedef struct
{
    const uint8_t *ptr; // wire format; may end with a compression pointer
    size_t         len; // octets at ptr (wire format, not limited to DNS_NAME_MAX)
} dns_name_ref_t;

typedef struct
{
    uint8_t *ptr; // wire format
    size_t   len; // octets used at ptr
    size_t   cap; // octets available at ptr
} dns_name_t;

// dns_name_t <--> dns_name_ref_t
dns_error_t
dns_name_to_ref (const dns_name_t *self, dns_name_ref_t *value);
dns_error_t
dns_name_from_ref (dns_name_t *self, const dns_name_ref_t *value);

// dns_name_ref_t <--> uint8_t * (wire format)
dns_error_t
dns_name_from_wire (dns_cursor_t *p, dns_name_ref_t *out);
dns_error_t
dns_name_to_wire (dns_cursor_t *p, const dns_name_ref_t *name, bool compress);

// dns_name_t <-- text, dns_name_ref_t --> text
dns_error_t
dns_name_from_string (dns_name_t *self, const char *str);
dns_error_t
dns_name_to_string (const dns_name_ref_t *self, GString *gs);

// compressed --> uncompressed
dns_error_t
dns_name_to_uncompressed (const dns_name_ref_t *self, const dns_cursor_t *p, dns_name_t *value);

// length
dns_error_t
dns_name_to_uncompressed_length (const dns_cursor_t *p, const dns_name_ref_t *name, size_t *len);

// check
dns_error_t
dns_name_check_uncompressed (const dns_name_ref_t *name);

// debug
GString *
dns_name_debug (const dns_name_ref_t *self, GString *gs);

#endif
