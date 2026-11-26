#ifndef DNSD_DNS_RECORD_H
#define DNSD_DNS_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"
#include "dns/params/class.h"
#include "dns/params/type.h"
#include "dns/rdata.h"

#define DNS_RECORD_DISPLAY_SIZE 4096
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
dns_record_to_bytes (dns_cursor_t *p, const dns_record_t *rr);
dns_error_t
dns_record_to_bytes_with_compress (dns_cursor_t *p, const dns_record_t *rr);

// compressed --> expanded
dns_error_t
dns_record_expand (const dns_cursor_t *p,
                   const dns_record_t *rr,
                   dns_name_t          names[DNS_RECORD_NAMES_MAX],
                   dns_record_t       *out);

// display
const char *
dns_record_display_r (const dns_record_t *rr, char *buf, size_t len);

#define dns_record_display(rr)                                                                     \
    dns_record_display_r ((rr), (char[DNS_RECORD_DISPLAY_SIZE]){}, DNS_RECORD_DISPLAY_SIZE)

#endif
