#ifndef DNSD_DNS_RDATA_CNAME_H
#define DNSD_DNS_RDATA_CNAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"

// cname points into the message it was read from.
typedef struct
{
    dns_name_ref_t cname;
} dns_rdata_cname_t;

// dns_rdata_cname_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_cname_from_wire (dns_cursor_t *p, size_t len, dns_rdata_cname_t *out);
dns_error_t
dns_rdata_cname_to_wire (dns_cursor_t *p, const dns_rdata_cname_t *rdata, bool compress);
size_t
dns_rdata_cname_length (const dns_rdata_cname_t *rdata);

#endif
