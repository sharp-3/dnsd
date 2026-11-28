#ifndef DNSD_DNS_RDATA_MINFO_H
#define DNSD_DNS_RDATA_MINFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"

// rmailbx and emailbx point into the message they were read from.
typedef struct
{
    dns_name_ref_t rmailbx; // mailbox responsible for the mailing list or mailbox
    dns_name_ref_t emailbx; // mailbox to receive error messages
} dns_rdata_minfo_t;        // MINFO: mailbox or mail list information

// dns_rdata_minfo_t <--> uint8_t * (wire format)
dns_error_t
dns_rdata_minfo_from_wire (dns_cursor_t *p, size_t len, dns_rdata_minfo_t *out);
dns_error_t
dns_rdata_minfo_to_wire (dns_cursor_t *p, const dns_rdata_minfo_t *rdata, bool compress);
size_t
dns_rdata_minfo_length (const dns_rdata_minfo_t *rdata);

#endif
