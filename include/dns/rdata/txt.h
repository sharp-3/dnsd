#ifndef DNSD_DNS_RDATA_TXT_H
#define DNSD_DNS_RDATA_TXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"

// data points into the message it was read from.
typedef struct
{
    const uint8_t *data; // one or more <character-string>s (length octet + octets)
    size_t         len;
} dns_rdata_txt_t;

// dns_rdata_txt_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_txt_from_wire (dns_cursor_t *p, size_t len, dns_rdata_txt_t *out);
dns_error_t
dns_rdata_txt_to_wire (dns_cursor_t *p, const dns_rdata_txt_t *rdata, bool compress);

#endif
