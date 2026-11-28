#ifndef DNSD_DNS_RDATA_MB_H
#define DNSD_DNS_RDATA_MB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"

// madname points into the message it was read from.
typedef struct
{
    dns_name_ref_t madname;
} dns_rdata_mb_t; // MB: mailbox domain name (experimental)

// dns_rdata_mb_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_mb_from_wire (dns_cursor_t *p, size_t len, dns_rdata_mb_t *out);
dns_error_t
dns_rdata_mb_to_wire (dns_cursor_t *p, const dns_rdata_mb_t *rdata, bool compress);

#endif
