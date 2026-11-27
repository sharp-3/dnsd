#ifndef DNSD_DNS_RDATA_SRV_H
#define DNSD_DNS_RDATA_SRV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"

// target points into the message it was read from.
typedef struct
{
    uint16_t       priority;
    uint16_t       weight;
    uint16_t       port;
    dns_name_ref_t target;
} dns_rdata_srv_t; // RFC 2782

// dns_rdata_srv_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_srv_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_srv_t *out);
dns_error_t
dns_rdata_srv_to_bytes (dns_cursor_t *p, const dns_rdata_srv_t *rdata, bool compress);
size_t
dns_rdata_srv_length (const dns_rdata_srv_t *rdata);

#endif
