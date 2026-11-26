#ifndef DNSD_DNS_NAME_H
#define DNSD_DNS_NAME_H

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/label.h"

#define DNS_NAME_MAX 255
#define DNS_NAME_STRING_SIZE (DNS_NAME_MAX * DNS_LABEL_ESCAPE_SIZE + 1)
#define DNS_NAME_DEBUG_SIZE (DNS_NAME_MAX * DNS_LABEL_ESCAPE_SIZE + sizeof "[pointer 0x3FFF]")

typedef struct
{
    const uint8_t *ptr; // wire format; may end with a compression pointer
    size_t         len; // octets at ptr (wire format, not limited to DNS_NAME_MAX)
} dns_name_ref_t;

// A name written into storage the caller provides (ptr, cap); a dns_name_ref_t to it comes from
// dns_name_to_ref.
typedef struct
{
    uint8_t *ptr; // wire format
    size_t   len; // octets used at ptr
    size_t   cap; // octets available at ptr
} dns_name_t;

// dns_name_t <--> dns_name_ref_t
dns_name_ref_t
dns_name_to_ref (const dns_name_t *name);
dns_error_t
dns_name_to_owned (const dns_name_ref_t *ref, dns_name_t *out);

// dns_name_ref_t <--> uint8_t * (wire format)
dns_error_t
dns_name_from_bytes (dns_cursor_t *p, dns_name_ref_t *out);
dns_error_t
dns_name_to_bytes (dns_cursor_t *p, const dns_name_ref_t *name);
// Writes the (uncompressed) name, ending it with a pointer to the longest suffix already in the
// message.
dns_error_t
dns_name_to_bytes_with_compress (dns_cursor_t *p, const dns_name_ref_t *name);

// dns_name_ref_t <--> char * (string)
dns_error_t
dns_name_from_string (const char *str, dns_name_t *out);
dns_error_t
dns_name_to_string (const dns_name_ref_t *name, char *buf, size_t len);

// compressed --> expanded
dns_error_t
dns_name_expand (const dns_cursor_t *p, const dns_name_ref_t *name, dns_name_t *out);

// length
dns_error_t
dns_name_length (const dns_cursor_t *p, size_t *size);
dns_error_t
dns_name_expand_length (const dns_cursor_t *p, const dns_name_ref_t *name, size_t *len);

// check
dns_error_t
dns_name_check_uncompressed (const dns_name_ref_t *name);

// debug
const char *
dns_name_debug_r (const dns_name_ref_t *name, char *buf, size_t len);
#define dns_name_debug(name)                                                                       \
    dns_name_debug_r ((name), (char[DNS_NAME_DEBUG_SIZE]){}, DNS_NAME_DEBUG_SIZE)

#endif
