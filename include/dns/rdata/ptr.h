#ifndef DNSD_DNS_RDATA_PTR_H
#define DNSD_DNS_RDATA_PTR_H

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"

// ptrdname points into the message it was read from.
typedef struct
{
    dns_name_ref_t ptrdname;
} dns_rdata_ptr_t;

// dns_rdata_ptr_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_ptr_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_ptr_t *out);
dns_error_t
dns_rdata_ptr_to_bytes (dns_cursor_t *p, const dns_rdata_ptr_t *rdata);
size_t
dns_rdata_ptr_length (const dns_rdata_ptr_t *rdata);

// compressed <--> expanded
dns_error_t
dns_rdata_ptr_expand (const dns_cursor_t    *p,
                      const dns_rdata_ptr_t *rdata,
                      dns_name_t            *name,
                      dns_rdata_ptr_t       *out);
dns_error_t
dns_rdata_ptr_compress (const dns_cursor_t    *p,
                        const dns_rdata_ptr_t *rdata,
                        dns_name_t            *name,
                        dns_rdata_ptr_t       *out);

#endif
