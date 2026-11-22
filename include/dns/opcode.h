#ifndef DNSD_DNS_OPCODE_H
#define DNSD_DNS_OPCODE_H

#include <stddef.h>
#include <stdint.h>

#define DNS_OPCODE_DISPLAY_SIZE sizeof "OPCODE255"

typedef enum : uint8_t
{
    DNS_OPCODE_QUERY  = 0, // standard query
    DNS_OPCODE_IQUERY = 1, // inverse query, obsolete (RFC 3425)
    DNS_OPCODE_STATUS = 2, // server status request
    DNS_OPCODE_NOTIFY = 4, // zone change notification (RFC 1996)
    DNS_OPCODE_UPDATE = 5, // dynamic update (RFC 2136)
    DNS_OPCODE_DSO    = 6, // DNS stateful operations (RFC 8490)
} dns_opcode_t;

const char *
dns_opcode_display_r (dns_opcode_t value, char *buf, size_t len);

#define dns_opcode_display(value)                                                                  \
    dns_opcode_display_r ((value), (char[DNS_OPCODE_DISPLAY_SIZE]){}, DNS_OPCODE_DISPLAY_SIZE)

#endif
