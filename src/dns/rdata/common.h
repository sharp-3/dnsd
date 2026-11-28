#ifndef DNSD_DNS_RDATA_COMMON_H
#define DNSD_DNS_RDATA_COMMON_H

// Shared by the per-type RDATA files and rdata.c; not part of the public API.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <glib.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"
#include "dns/rdata.h"
#include "packet/cursor.h"

// end of reading / writing RDATA
dns_error_t
rdata_end (dns_cursor_t *p, const cursor_t *start, dns_error_t err, dns_error_t overflow_err);

// RDATA made of a single name (NS, CNAME, PTR, DNAME)
dns_error_t
rdata_name_from_wire (dns_cursor_t *p, size_t len, dns_name_ref_t *out);
dns_error_t
rdata_name_to_wire (dns_cursor_t *p, const dns_name_ref_t *name, bool compress);

// debug: append to gs
void
rdata_name_debug (const dns_name_ref_t *self, GString *gs);
void
rdata_a_debug (const dns_rdata_a_t *self, GString *gs);
void
rdata_aaaa_debug (const dns_rdata_aaaa_t *self, GString *gs);
void
rdata_ns_debug (const dns_rdata_ns_t *self, GString *gs);
void
rdata_cname_debug (const dns_rdata_cname_t *self, GString *gs);
void
rdata_ptr_debug (const dns_rdata_ptr_t *self, GString *gs);
void
rdata_dname_debug (const dns_rdata_dname_t *self, GString *gs);
void
rdata_mx_debug (const dns_rdata_mx_t *self, GString *gs);
void
rdata_srv_debug (const dns_rdata_srv_t *self, GString *gs);
void
rdata_soa_debug (const dns_rdata_soa_t *self, GString *gs);
void
rdata_md_debug (const dns_rdata_md_t *self, GString *gs);
void
rdata_mf_debug (const dns_rdata_mf_t *self, GString *gs);
void
rdata_mb_debug (const dns_rdata_mb_t *self, GString *gs);
void
rdata_mg_debug (const dns_rdata_mg_t *self, GString *gs);
void
rdata_mr_debug (const dns_rdata_mr_t *self, GString *gs);
void
rdata_minfo_debug (const dns_rdata_minfo_t *self, GString *gs);
void
rdata_txt_debug (const dns_rdata_txt_t *self, GString *gs);
void
rdata_unknown_debug (const dns_rdata_unknown_t *self, GString *gs);

#endif
