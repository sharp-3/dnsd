#ifndef DNSD_DNS_RDATA_MF_H
#define DNSD_DNS_RDATA_MF_H

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
} dns_rdata_mf_t; // MF: mail forwarder (obsolete: use MX)

// dns_rdata_mf_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_mf_from_wire (dns_cursor_t *p, size_t len, dns_rdata_mf_t *out);
dns_error_t
dns_rdata_mf_to_wire (dns_cursor_t *p, const dns_rdata_mf_t *rdata, bool compress);
size_t
dns_rdata_mf_length (const dns_rdata_mf_t *rdata);

#endif
