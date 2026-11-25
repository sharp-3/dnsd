#ifndef DNSD_DNS_RDATA_COMMON_H
#define DNSD_DNS_RDATA_COMMON_H

// Shared by the per-type RDATA files and rdata.c; not part of the public API.

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"
#include "dns/rdata.h"
#include "packet/cursor.h"

// reading RDATA
dns_error_t
rdata_begin (dns_cursor_t *p, size_t len, cursor_t *start);
dns_error_t
rdata_end (dns_cursor_t *p, const cursor_t *start, dns_error_t err);

// writing RDATA
dns_error_t
rdata_put_end (dns_cursor_t *p, const cursor_t *start, dns_error_t err);

// RDATA made of a single name (NS, CNAME, PTR, DNAME)
dns_error_t
rdata_name_from_bytes (dns_cursor_t *p, size_t len, dns_name_t *out);
dns_error_t
rdata_name_to_bytes (dns_cursor_t *p, const dns_name_t *name);

// per-type length
size_t
rdata_a_length (const dns_rdata_a_t *rd);
size_t
rdata_aaaa_length (const dns_rdata_aaaa_t *rd);
size_t
rdata_ns_length (const dns_rdata_ns_t *rd);
size_t
rdata_cname_length (const dns_rdata_cname_t *rd);
size_t
rdata_ptr_length (const dns_rdata_ptr_t *rd);
size_t
rdata_dname_length (const dns_rdata_dname_t *rd);
size_t
rdata_mx_length (const dns_rdata_mx_t *rd);
size_t
rdata_srv_length (const dns_rdata_srv_t *rd);
size_t
rdata_soa_length (const dns_rdata_soa_t *rd);
size_t
rdata_txt_length (const dns_rdata_txt_t *rd);
size_t
rdata_unknown_length (const dns_rdata_unknown_t *rd);

// display
void
rdata_name_display (const dns_name_t *name, char *buf, size_t len);
void
rdata_a_display (const dns_rdata_a_t *rd, char *buf, size_t len);
void
rdata_aaaa_display (const dns_rdata_aaaa_t *rd, char *buf, size_t len);
void
rdata_ns_display (const dns_rdata_ns_t *rd, char *buf, size_t len);
void
rdata_cname_display (const dns_rdata_cname_t *rd, char *buf, size_t len);
void
rdata_ptr_display (const dns_rdata_ptr_t *rd, char *buf, size_t len);
void
rdata_dname_display (const dns_rdata_dname_t *rd, char *buf, size_t len);
void
rdata_mx_display (const dns_rdata_mx_t *rd, char *buf, size_t len);
void
rdata_srv_display (const dns_rdata_srv_t *rd, char *buf, size_t len);
void
rdata_soa_display (const dns_rdata_soa_t *rd, char *buf, size_t len);
void
rdata_txt_display (const dns_rdata_txt_t *rd, char *buf, size_t len);
void
rdata_unknown_display (const dns_rdata_unknown_t *rd, char *buf, size_t len);

#endif
