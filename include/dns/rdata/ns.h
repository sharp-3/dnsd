#ifndef DNSD_DNS_RDATA_NS_H
#define DNSD_DNS_RDATA_NS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"

// nsdname points into the message it was read from.
typedef struct
{
    dns_name_ref_t nsdname;
} dns_rdata_ns_t;

// dns_rdata_ns_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_ns_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_ns_t *out);
dns_error_t
dns_rdata_ns_to_bytes (dns_cursor_t *p, const dns_rdata_ns_t *rdata, bool compress);
size_t
dns_rdata_ns_length (const dns_rdata_ns_t *rdata);

// compressed --> uncompressed
dns_error_t
dns_rdata_ns_to_uncompressed (const dns_cursor_t   *p,
                              const dns_rdata_ns_t *rdata,
                              dns_name_t           *name,
                              dns_rdata_ns_t       *out);

#endif
