#ifndef DNSD_DNS_PARAMS_RCODE_H
#define DNSD_DNS_PARAMS_RCODE_H

#include <stddef.h>
#include <stdint.h>

#include <glib.h>

#include "dns/error.h"

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

// dns_rcode_t <--> text
dns_error_t
dns_rcode_from_string (dns_rcode_t *self, const char *str);
dns_error_t
dns_rcode_to_string (dns_rcode_t self, GString *gs);

#endif
