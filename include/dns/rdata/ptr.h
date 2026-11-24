#ifndef DNSD_DNS_RDATA_PTR_H
#define DNSD_DNS_RDATA_PTR_H

#include <stddef.h>
#include <stdint.h>

#include "dns/error.h"
#include "dns/name.h"
#include "dns/parser.h"

// ptrdname points into the message it was read from.
typedef struct
{
    dns_name_t ptrdname;
} dns_rdata_ptr_t;

dns_error_t
dns_rdata_ptr_from_bytes (dns_parser_t *p, size_t len, dns_rdata_ptr_t *out);
dns_error_t
dns_rdata_ptr_to_bytes (dns_parser_t *p, const dns_rdata_ptr_t *rdata);

#endif
