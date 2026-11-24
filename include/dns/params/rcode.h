#ifndef DNSD_DNS_PARAMS_RCODE_H
#define DNSD_DNS_PARAMS_RCODE_H

#include <stddef.h>
#include <stdint.h>

#include "dns/error.h"

#define DNS_RCODE_DISPLAY_SIZE sizeof "RCODE255"
#define DNS_RCODE_MAX 15 // RCODE is a 4-bit header field (EDNS extended RCODE not handled)

typedef enum : uint8_t
{
    DNS_RCODE_NOERROR   = 0,  // no error
    DNS_RCODE_FORMERR   = 1,  // format error
    DNS_RCODE_SERVFAIL  = 2,  // server failure
    DNS_RCODE_NXDOMAIN  = 3,  // name does not exist
    DNS_RCODE_NOTIMP    = 4,  // not implemented
    DNS_RCODE_REFUSED   = 5,  // refused
    DNS_RCODE_YXDOMAIN  = 6,  // name exists when it should not (RFC 2136)
    DNS_RCODE_YXRRSET   = 7,  // RRset exists when it should not (RFC 2136)
    DNS_RCODE_NXRRSET   = 8,  // RRset that should exist does not (RFC 2136)
    DNS_RCODE_NOTAUTH   = 9,  // not authoritative (RFC 2136)
    DNS_RCODE_NOTZONE   = 10, // name not in zone (RFC 2136)
    DNS_RCODE_DSOTYPENI = 11, // DSO-TYPE not implemented (RFC 8490)
} dns_rcode_t;

// Parses the mnemonic (e.g. "NXDOMAIN", ignoring ASCII case) or the generic form "RCODE<n>"
// (n decimal, 0..DNS_RCODE_MAX; the form dns_rcode_display uses for unknown values) into *out.
// DNS_ERR_BAD_TEXT: neither form; *out is unchanged.
dns_error_t
dns_rcode_from_string (const char *str, dns_rcode_t *out);

const char *
dns_rcode_display_r (dns_rcode_t value, char *buf, size_t len);

#define dns_rcode_display(value)                                                                   \
    dns_rcode_display_r ((value), (char[DNS_RCODE_DISPLAY_SIZE]){}, DNS_RCODE_DISPLAY_SIZE)

#endif
