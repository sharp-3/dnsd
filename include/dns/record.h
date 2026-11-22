#ifndef DNSD_DNS_RECORD_H
#define DNSD_DNS_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include "dns/class.h"
#include "dns/error.h"
#include "dns/name.h"
#include "dns/parser.h"
#include "dns/rdata.h"
#include "dns/type.h"

#define DNS_RECORD_DISPLAY_SIZE 4096

// name and rdata point into the message they were read from; keep it alive while rr is used.
typedef struct
{
    dns_name_t  name;  // owner name
    dns_type_t  type;  // RR type
    dns_class_t class; // RR class
    uint32_t    ttl;   // seconds the record may be cached
    dns_rdata_t rdata; // RDATA; member chosen by type and class (see rdata.h)
} dns_record_t;

// Reads the record at p->cur and advances it; other errors leave p->cur unchanged.
// DNS_OK_NAME_TOO_LONG (name over DNS_NAME_MAX octets) still fills *out and advances p->cur;
// other errors leave *out unchanged.
dns_error_t
dns_record_from_bytes (dns_parser_t *p, dns_record_t *out);
// Writes the record at p->cur and advances it; other errors leave p->cur unchanged.
// DNS_OK_NAME_TOO_LONG (name over DNS_NAME_MAX octets) still writes and advances p->cur.
dns_error_t
dns_record_to_bytes (dns_parser_t *p, const dns_record_t *rr);

const char *
dns_record_display_r (const dns_record_t *rr, char *buf, size_t len);

#define dns_record_display(rr)                                                                     \
    dns_record_display_r ((rr), (char[DNS_RECORD_DISPLAY_SIZE]){}, DNS_RECORD_DISPLAY_SIZE)

#endif
