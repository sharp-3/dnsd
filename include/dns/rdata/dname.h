#ifndef DNSD_DNS_RDATA_DNAME_H
#define DNSD_DNS_RDATA_DNAME_H

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"

// target points into the message it was read from.
typedef struct
{
    dns_name_ref_t target;
} dns_rdata_dname_t; // RFC 6672

// dns_rdata_dname_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_dname_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_dname_t *out);
dns_error_t
dns_rdata_dname_to_bytes (dns_cursor_t *p, const dns_rdata_dname_t *rdata);
dns_error_t
dns_rdata_dname_to_bytes_with_compress (dns_cursor_t *p, const dns_rdata_dname_t *rdata);
size_t
dns_rdata_dname_length (const dns_rdata_dname_t *rdata);

// compressed --> expanded
dns_error_t
dns_rdata_dname_expand (const dns_cursor_t      *p,
                        const dns_rdata_dname_t *rdata,
                        dns_name_t              *name,
                        dns_rdata_dname_t       *out);

#endif
