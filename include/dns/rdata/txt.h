#ifndef DNSD_DNS_RDATA_TXT_H
#define DNSD_DNS_RDATA_TXT_H

#include <stddef.h>
#include <stdint.h>

#include "dns/error.h"
#include "dns/parser.h"

// data points into the message it was read from.
typedef struct
{
    const uint8_t *data; // one or more <character-string>s (length octet + octets)
    size_t         len;
} dns_rdata_txt_t;

dns_error_t
dns_rdata_txt_from_bytes (dns_parser_t *p, size_t len, dns_rdata_txt_t *out);
dns_error_t
dns_rdata_txt_to_bytes (dns_parser_t *p, const dns_rdata_txt_t *rdata);

#endif
