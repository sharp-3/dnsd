#ifndef DNSD_DNS_NAME_H
#define DNSD_DNS_NAME_H

#include <stddef.h>
#include <stdint.h>

#include "dns/error.h"
#include "dns/label.h"
#include "dns/parser.h"

#define DNS_NAME_MAX 255
#define DNS_NAME_STRING_SIZE (DNS_NAME_MAX * DNS_LABEL_ESCAPE_SIZE + 1)
#define DNS_NAME_DEBUG_SIZE (DNS_NAME_MAX * DNS_LABEL_ESCAPE_SIZE + sizeof "[pointer 0x3FFF]")

typedef struct
{
    const uint8_t *ptr; // wire format; may end with a compression pointer
    size_t         len; // octets at ptr (wire format, not limited to DNS_NAME_MAX)
} dns_name_t;

// Reads the name at p->cur and advances it; other errors leave p->cur unchanged.
// DNS_OK_NAME_TOO_LONG (name over DNS_NAME_MAX octets) still fills *out and advances p->cur.
dns_error_t
dns_name_from_bytes (dns_parser_t *p, dns_name_t *out);
// Parses the presentation form str (absolute; "." is the root) and writes the name in wire format
// to buf (len octets); *out then points into buf, so keep buf alive while *out is used.
// strlen (str) + 2 octets always suffice; DNS_NAME_MAX octets hold any name that is not too long.
// DNS_OK_NAME_TOO_LONG (over DNS_NAME_MAX octets) still sets *out.
// DNS_ERR_NO_SPACE: the name does not fit in len octets.
// On error *out is unchanged and the contents of buf are unspecified.
dns_error_t
dns_name_from_string (const char *str, uint8_t *buf, size_t len, dns_name_t *out);
// Checks the name at p->cur like dns_name_from_bytes and stores its wire length in *size,
// without changing p (no cursor move, no label marking).
dns_error_t
dns_name_length (const dns_parser_t *p, size_t *size);
// Checks name like dns_name_expand and stores its length once expanded in *len.
// DNS_OK_NAME_TOO_LONG (over DNS_NAME_MAX octets once expanded) still sets *len.
dns_error_t
dns_name_expand_length (const dns_parser_t *p, const dns_name_t *name, size_t *len);
// Follows the compression pointers in name and writes the uncompressed name to buf (len
// octets); *out then points into buf, so keep buf alive while *out is used. DNS_NAME_MAX octets
// hold any name that is not too long; a longer one needs up to the message size.
// DNS_OK_NAME_TOO_LONG (over DNS_NAME_MAX octets once expanded) still sets *out.
// DNS_ERR_NO_SPACE: the expanded name does not fit in len octets.
// On error *out is unchanged and the contents of buf are unspecified.
dns_error_t
dns_name_expand (
    const dns_parser_t *p, const dns_name_t *name, uint8_t *buf, size_t len, dns_name_t *out);
// Writes the name at p->cur and advances it; other errors leave p->cur unchanged.
// DNS_OK_NAME_TOO_LONG (name over DNS_NAME_MAX octets) still writes and advances p->cur.
dns_error_t
dns_name_to_bytes (dns_parser_t *p, const dns_name_t *name);
dns_error_t
dns_name_to_string (const dns_name_t *name, char *buf, size_t len);
const char *
dns_name_debug_r (const dns_name_t *name, char *buf, size_t len);
#define dns_name_debug(name)                                                                       \
    dns_name_debug_r ((name), (char[DNS_NAME_DEBUG_SIZE]){}, DNS_NAME_DEBUG_SIZE)

#endif
