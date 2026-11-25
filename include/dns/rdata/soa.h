#ifndef DNSD_DNS_RDATA_SOA_H
#define DNSD_DNS_RDATA_SOA_H

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"

// mname and rname point into the message they were read from.
typedef struct
{
    dns_name_ref_t mname;
    dns_name_ref_t rname;
    uint32_t       serial;
    uint32_t       refresh;
    uint32_t       retry;
    uint32_t       expire;
    uint32_t       minimum;
} dns_rdata_soa_t;

// dns_rdata_soa_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_soa_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_soa_t *out);
dns_error_t
dns_rdata_soa_to_bytes (dns_cursor_t *p, const dns_rdata_soa_t *rdata);
size_t
dns_rdata_soa_length (const dns_rdata_soa_t *rdata);

// compressed <--> expanded
dns_error_t
dns_rdata_soa_expand (const dns_cursor_t    *p,
                      const dns_rdata_soa_t *rdata,
                      dns_name_t             names[2],
                      dns_rdata_soa_t       *out);
dns_error_t
dns_rdata_soa_compress (const dns_cursor_t    *p,
                        const dns_rdata_soa_t *rdata,
                        dns_name_t             names[2],
                        dns_rdata_soa_t       *out);

#endif
