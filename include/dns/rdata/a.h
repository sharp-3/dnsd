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

bool
dns_rdata_a_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_a_t *out);
bool
dns_rdata_a_to_bytes (dns_cursor_t *p, const dns_rdata_a_t *rdata);

#endif
