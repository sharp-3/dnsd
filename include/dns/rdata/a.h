#ifndef DNSD_DNS_RDATA_A_H
#define DNSD_DNS_RDATA_A_H

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"

typedef struct
{
    uint8_t addr[4];
} dns_rdata_a_t; // A (class IN)

// dns_rdata_a_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_a_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_a_t *out);
dns_error_t
dns_rdata_a_to_bytes (dns_cursor_t *p, const dns_rdata_a_t *rdata);
size_t
dns_rdata_a_length (const dns_rdata_a_t *rdata);

// compressed <--> expanded
dns_error_t
dns_rdata_a_expand (const dns_cursor_t *p, const dns_rdata_a_t *rdata, dns_rdata_a_t *out);
dns_error_t
dns_rdata_a_compress (const dns_cursor_t *p, const dns_rdata_a_t *rdata, dns_rdata_a_t *out);

#endif
