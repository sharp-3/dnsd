#ifndef DNSD_DNS_RDATA_MX_H
#define DNSD_DNS_RDATA_MX_H

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"

// exchange points into the message it was read from.
typedef struct
{
    uint16_t       preference;
    dns_name_ref_t exchange;
} dns_rdata_mx_t;

// dns_rdata_mx_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_mx_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_mx_t *out);
dns_error_t
dns_rdata_mx_to_bytes (dns_cursor_t *p, const dns_rdata_mx_t *rdata);
dns_error_t
dns_rdata_mx_to_bytes_with_compress (dns_cursor_t *p, const dns_rdata_mx_t *rdata);
size_t
dns_rdata_mx_length (const dns_rdata_mx_t *rdata);

// compressed --> expanded
dns_error_t
dns_rdata_mx_expand (const dns_cursor_t   *p,
                     const dns_rdata_mx_t *rdata,
                     dns_name_t           *name,
                     dns_rdata_mx_t       *out);

#endif
