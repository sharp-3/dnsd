#ifndef DNSD_DNS_RDATA_TXT_H
#define DNSD_DNS_RDATA_TXT_H

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

bool
dns_rdata_txt_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_txt_t *out);
bool
dns_rdata_txt_to_bytes (dns_cursor_t *p, const dns_rdata_txt_t *rdata);

#endif
