#ifndef DNSD_DNS_RDATA_MX_H
#define DNSD_DNS_RDATA_MX_H

#include <stdbool.h>
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
dns_rdata_mx_from_wire (dns_cursor_t *p, size_t len, dns_rdata_mx_t *out);
dns_error_t
dns_rdata_mx_to_wire (dns_cursor_t *p, const dns_rdata_mx_t *rdata, bool compress);
size_t
dns_rdata_mx_length (const dns_rdata_mx_t *rdata);

#endif
