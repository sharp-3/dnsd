#ifndef DNSD_DNS_RDATA_UNKNOWN_H
#define DNSD_DNS_RDATA_UNKNOWN_H

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"

// RDATA of a (type, class) without its own member in dns_rdata_t, kept as is (RFC 3597).
// data points into the message it was read from.
typedef struct
{
    const uint8_t *data;
    size_t         len;
} dns_rdata_unknown_t;

dns_error_t
dns_rdata_unknown_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_unknown_t *out);
dns_error_t
dns_rdata_unknown_to_bytes (dns_cursor_t *p, const dns_rdata_unknown_t *rdata);

#endif
