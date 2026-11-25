#ifndef DNSD_DNS_PARAMS_TYPE_H
#define DNSD_DNS_PARAMS_TYPE_H

#include <stddef.h>
#include <stdint.h>

#include "dns/error.h"

#define DNS_TYPE_SIZE 2 // octets in wire format
#define DNS_TYPE_DISPLAY_SIZE sizeof "TYPE65535"

typedef enum : uint16_t
{
    DNS_TYPE_A          = 1,   // IPv4 address
    DNS_TYPE_NS         = 2,   // name server
    DNS_TYPE_CNAME      = 5,   // canonical name
    DNS_TYPE_SOA        = 6,   // start of authority
    DNS_TYPE_PTR        = 12,  // domain name pointer
    DNS_TYPE_HINFO      = 13,  // host information
    DNS_TYPE_MX         = 15,  // mail exchange
    DNS_TYPE_TXT        = 16,  // text strings
    DNS_TYPE_AAAA       = 28,  // IPv6 address (RFC 3596)
    DNS_TYPE_SRV        = 33,  // service location (RFC 2782)
    DNS_TYPE_NAPTR      = 35,  // naming authority pointer (RFC 3403)
    DNS_TYPE_DNAME      = 39,  // delegation name (RFC 6672)
    DNS_TYPE_OPT        = 41,  // EDNS option (RFC 6891)
    DNS_TYPE_DS         = 43,  // delegation signer (RFC 4034)
    DNS_TYPE_SSHFP      = 44,  // SSH key fingerprint (RFC 4255)
    DNS_TYPE_RRSIG      = 46,  // RRset signature (RFC 4034)
    DNS_TYPE_NSEC       = 47,  // next secure (RFC 4034)
    DNS_TYPE_DNSKEY     = 48,  // DNS key (RFC 4034)
    DNS_TYPE_NSEC3      = 50,  // hashed next secure (RFC 5155)
    DNS_TYPE_NSEC3PARAM = 51,  // NSEC3 parameters (RFC 5155)
    DNS_TYPE_TLSA       = 52,  // TLS certificate association (RFC 6698)
    DNS_TYPE_SVCB       = 64,  // service binding (RFC 9460)
    DNS_TYPE_HTTPS      = 65,  // HTTPS binding (RFC 9460)
    DNS_TYPE_IXFR       = 251, // incremental zone transfer (QTYPE only)
    DNS_TYPE_AXFR       = 252, // zone transfer (QTYPE only)
    DNS_TYPE_ANY        = 255, // all records (QTYPE only)
    DNS_TYPE_CAA        = 257, // certification authority authorization (RFC 8659)
} dns_type_t;

// category (RFC 6895 3.1)
bool
dns_type_is_data (dns_type_t type);
bool
dns_type_is_qonly_or_meta (dns_type_t type);
bool
dns_type_is_reserved (dns_type_t type);

// dns_type_t <-- char * (string)
dns_error_t
dns_type_from_string (const char *str, dns_type_t *out);

// display
const char *
dns_type_display_r (dns_type_t value, char *buf, size_t len);
#define dns_type_display(value)                                                                    \
    dns_type_display_r ((value), (char[DNS_TYPE_DISPLAY_SIZE]){}, DNS_TYPE_DISPLAY_SIZE)

#endif
