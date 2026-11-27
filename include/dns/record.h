#ifndef DNSD_DNS_RECORD_H
#define DNSD_DNS_RECORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"
#include "dns/params/class.h"
#include "dns/params/type.h"
#include "dns/rdata.h"

#define DNS_RECORD_DEBUG_SIZE 4096
#define DNS_RECORD_NAMES_MAX (1 + DNS_RDATA_NAMES_MAX) // owner name and RDATA names

// name and rdata point into the message they were read from; keep it alive while rr is used.
typedef struct
{
    dns_name_ref_t name;  // owner name
    dns_type_t     type;  // RR type
    dns_class_t    class; // RR class
    uint32_t       ttl;   // seconds the record may be cached
    dns_rdata_t    rdata; // RDATA; member chosen by type and class (see rdata.h)
} dns_record_t;

// dns_record_t <--> uint8_t * (wire format)
dns_error_t
dns_record_from_bytes (dns_cursor_t *p, dns_record_t *out);
dns_error_t
dns_record_to_bytes (dns_cursor_t *p, const dns_record_t *rr, bool compress);

// debug
const char *
dns_record_debug_r (const dns_record_t *rr, char *buf, size_t len);

#define dns_record_debug(rr)                                                                       \
    dns_record_debug_r ((rr), (char[DNS_RECORD_DEBUG_SIZE]){}, DNS_RECORD_DEBUG_SIZE)

#endif
