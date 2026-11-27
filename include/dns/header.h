#ifndef DNSD_DNS_HEADER_H
#define DNSD_DNS_HEADER_H

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/params/opcode.h"
#include "dns/params/rcode.h"

#define DNS_HEADER_SIZE 12
#define DNS_HEADER_DEBUG_SIZE                                                                      \
    sizeof "id=0xFFFF qr aa tc rd ra z ad cd opcode=OPCODE255 rcode=RCODE255 "                     \
           "qdcount=65535 ancount=65535 nscount=65535 arcount=65535"

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
dns_header_from_bytes (dns_cursor_t *p, dns_header_t *out);
dns_error_t
dns_header_to_bytes (dns_cursor_t *p, const dns_header_t *hdr);

// debug
const char *
dns_header_debug_r (const dns_header_t *hdr, char *buf, size_t len);
#define dns_header_debug(hdr)                                                                      \
    dns_header_debug_r ((hdr), (char[DNS_HEADER_DEBUG_SIZE]){}, DNS_HEADER_DEBUG_SIZE)

#endif
