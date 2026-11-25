#ifndef DNSD_DNS_RDATA_AAAA_H
#define DNSD_DNS_RDATA_AAAA_H

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"

typedef struct
{
    uint8_t addr[16];
} dns_rdata_aaaa_t; // AAAA (class IN, RFC 3596)

// dns_rdata_aaaa_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_aaaa_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_aaaa_t *out);
dns_error_t
dns_rdata_aaaa_to_bytes (dns_cursor_t *p, const dns_rdata_aaaa_t *rdata);

#endif
