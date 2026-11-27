#ifndef DNSD_DNS_RDATA_MD_H
#define DNSD_DNS_RDATA_MD_H

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
} dns_rdata_md_t; // MD: mail destination (obsolete: use MX)

// dns_rdata_md_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_md_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_md_t *out);
dns_error_t
dns_rdata_md_to_bytes (dns_cursor_t *p, const dns_rdata_md_t *rdata, bool compress);
size_t
dns_rdata_md_length (const dns_rdata_md_t *rdata);

#endif
