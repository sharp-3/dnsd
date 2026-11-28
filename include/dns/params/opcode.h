#ifndef DNSD_DNS_PARAMS_OPCODE_H
#define DNSD_DNS_PARAMS_OPCODE_H

#include <stddef.h>
#include <stdint.h>

#include <glib.h>

#include "dns/error.h"

#define DNS_OPCODE_MAX 15 // OPCODE is a 4-bit header field

typedef enum : uint8_t
{
    DNS_OPCODE_QUERY  = 0, // standard query
    DNS_OPCODE_IQUERY = 1, // inverse query, obsolete (RFC 3425)
    DNS_OPCODE_STATUS = 2, // server status request
    DNS_OPCODE_NOTIFY = 4, // zone change notification (RFC 1996)
    DNS_OPCODE_UPDATE = 5, // dynamic update (RFC 2136)
    DNS_OPCODE_DSO    = 6, // DNS stateful operations (RFC 8490)
} dns_opcode_t;

// dns_opcode_t <--> text
dns_error_t
dns_opcode_from_string (dns_opcode_t *self, const char *str);
dns_error_t
dns_opcode_to_string (dns_opcode_t self, GString *gs);

#endif
