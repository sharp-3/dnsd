#ifndef DNSD_DNS_RDATA_MG_H
#define DNSD_DNS_RDATA_MG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"

// mgmname points into the message it was read from.
typedef struct
{
    dns_name_ref_t mgmname;
} dns_rdata_mg_t; // MG: mail group member (experimental)

// dns_rdata_mg_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_mg_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_mg_t *out);
dns_error_t
dns_rdata_mg_to_bytes (dns_cursor_t *p, const dns_rdata_mg_t *rdata, bool compress);
size_t
dns_rdata_mg_length (const dns_rdata_mg_t *rdata);

#endif
