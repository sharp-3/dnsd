#ifndef DNSD_DNS_HEADER_H
#define DNSD_DNS_HEADER_H

#include <stddef.h>
#include <stdint.h>

#include <glib.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/params/opcode.h"
#include "dns/params/rcode.h"

#define DNS_HEADER_SIZE 12

typedef struct
{
    uint16_t     id;      // query identifier
    bool         qr;      // false = query, true = response
    dns_opcode_t opcode;  // kind of query
    bool         aa;      // authoritative answer
    bool         tc;      // truncated
    bool         rd;      // recursion desired
    bool         ra;      // recursion available
    bool         z;       // reserved, must be 0
    bool         ad;      // authentic data (RFC 4035)
    bool         cd;      // checking disabled (RFC 4035)
    dns_rcode_t  rcode;   // response code
    uint16_t     qdcount; // entries in the question section
    uint16_t     ancount; // records in the answer section
    uint16_t     nscount; // records in the authority section
    uint16_t     arcount; // records in the additional section
} dns_header_t;

// dns_header_t <--> uint8_t * (wire format)
dns_error_t
dns_header_from_wire (dns_cursor_t *p, dns_header_t *out);
dns_error_t
dns_header_to_wire (dns_cursor_t *p, const dns_header_t *hdr);

// debug
GString *
dns_header_debug (const dns_header_t *self, GString *gs);

#endif
