#ifndef DNSD_DNS_RDATA_MR_H
#define DNSD_DNS_RDATA_MR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"

// newname points into the message it was read from.
typedef struct
{
    dns_name_ref_t newname;
} dns_rdata_mr_t; // MR: mail rename (experimental)

// dns_rdata_mr_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_mr_from_wire (dns_cursor_t *p, size_t len, dns_rdata_mr_t *out);
dns_error_t
dns_rdata_mr_to_wire (dns_cursor_t *p, const dns_rdata_mr_t *rdata, bool compress);

#endif
