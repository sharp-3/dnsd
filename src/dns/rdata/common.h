#ifndef DNSD_DNS_RDATA_COMMON_H
#define DNSD_DNS_RDATA_COMMON_H

// Shared by the per-type RDATA files and rdata.c; not part of the public API.

#include <stddef.h>
#include <stdint.h>

#include "dns/error.h"
#include "dns/name.h"
#include "dns/parser.h"
#include "dns/rdata.h"
#include "packet/cursor.h"

// Limits p->cur to the len octets of RDATA at it, so that reading past them overflows (or
// truncates a name). Saves the cursor in *start for rdata_end.
dns_error_t
rdata_begin (dns_parser_t *p, size_t len, cursor_t *start);
// Ends what rdata_begin started, given the result err of reading the RDATA. Not reading it
// exactly (too much or too little) is DNS_ERR_BAD_RDATA. On success p->cur stays after the
// RDATA; on error it goes back to *start.
dns_error_t
rdata_end (dns_parser_t *p, const cursor_t *start, dns_error_t err);

// Ends a write of RDATA that started at *start: if it did not fit (or p->cur had already
// overflowed), p->cur goes back to *start and the result is DNS_ERR_NO_SPACE.
dns_error_t
rdata_put_end (dns_parser_t *p, const cursor_t *start);

// A single domain name filling the whole RDATA (NS, CNAME, PTR, DNAME).
dns_error_t
rdata_name_from_bytes (dns_parser_t *p, size_t len, dns_name_t *out);
dns_error_t
rdata_name_to_bytes (dns_parser_t *p, const dns_name_t *name);
void
rdata_name_display (const dns_name_t *name, char *buf, size_t len, size_t *out);

// Appends to buf (len octets in all) at *out, keeping it NUL-terminated; on overflow *out
// becomes len and later appends do nothing.
[[gnu::format (printf, 4, 5)]] void
rdata_appendf (char *buf, size_t len, size_t *out, const char *fmt, ...);
// Appends s (n octets) as a quoted <character-string>.
void
rdata_append_string (char *buf, size_t len, size_t *out, const uint8_t *s, size_t n);

// Per-type length (octets in wire format) and presentation form (appended to buf at *out).
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

void
rdata_a_display (const dns_rdata_a_t *rd, char *buf, size_t len, size_t *out);
void
rdata_aaaa_display (const dns_rdata_aaaa_t *rd, char *buf, size_t len, size_t *out);
void
rdata_ns_display (const dns_rdata_ns_t *rd, char *buf, size_t len, size_t *out);
void
rdata_cname_display (const dns_rdata_cname_t *rd, char *buf, size_t len, size_t *out);
void
rdata_ptr_display (const dns_rdata_ptr_t *rd, char *buf, size_t len, size_t *out);
void
rdata_dname_display (const dns_rdata_dname_t *rd, char *buf, size_t len, size_t *out);
void
rdata_mx_display (const dns_rdata_mx_t *rd, char *buf, size_t len, size_t *out);
void
rdata_srv_display (const dns_rdata_srv_t *rd, char *buf, size_t len, size_t *out);
void
rdata_soa_display (const dns_rdata_soa_t *rd, char *buf, size_t len, size_t *out);
void
rdata_txt_display (const dns_rdata_txt_t *rd, char *buf, size_t len, size_t *out);
// RFC 3597 generic form.
void
rdata_unknown_display (const dns_rdata_unknown_t *rd, char *buf, size_t len, size_t *out);

#endif
