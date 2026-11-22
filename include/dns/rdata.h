#ifndef DNSD_DNS_RDATA_H
#define DNSD_DNS_RDATA_H

#include <stddef.h>
#include <stdint.h>

#include "dns/class.h"
#include "dns/error.h"
#include "dns/name.h"
#include "dns/parser.h"
#include "dns/type.h"
#include "packet/cursor.h"

// Names below are in wire format and may end with a compression pointer; they point into the
// message the RDATA was read from.

typedef struct
{
    uint8_t addr[4];
} dns_rdata_a_t; // A (class IN)

typedef struct
{
    uint8_t addr[16];
} dns_rdata_aaaa_t; // AAAA (class IN, RFC 3596)

typedef struct
{
    dns_name_t nsdname;
} dns_rdata_ns_t;

typedef struct
{
    dns_name_t cname;
} dns_rdata_cname_t;

typedef struct
{
    dns_name_t ptrdname;
} dns_rdata_ptr_t;

typedef struct
{
    dns_name_t target;
} dns_rdata_dname_t; // RFC 6672

typedef struct
{
    uint16_t   preference;
    dns_name_t exchange;
} dns_rdata_mx_t;

typedef struct
{
    uint16_t   priority;
    uint16_t   weight;
    uint16_t   port;
    dns_name_t target;
} dns_rdata_srv_t; // RFC 2782

typedef struct
{
    dns_name_t mname;
    dns_name_t rname;
    uint32_t   serial;
    uint32_t   refresh;
    uint32_t   retry;
    uint32_t   expire;
    uint32_t   minimum;
} dns_rdata_soa_t;

typedef struct
{
    const uint8_t *data; // one or more <character-string>s (length octet + octets)
    size_t         len;
} dns_rdata_txt_t;

typedef struct
{
    const uint8_t *data;
    size_t         len;
} dns_rdata_unknown_t;

// The valid member is chosen by TYPE: .unknown when !dns_rdata_known (type, class).
typedef union
{
    dns_rdata_a_t       a;
    dns_rdata_aaaa_t    aaaa;
    dns_rdata_ns_t      ns;
    dns_rdata_cname_t   cname;
    dns_rdata_ptr_t     ptr;
    dns_rdata_dname_t   dname;
    dns_rdata_mx_t      mx;
    dns_rdata_srv_t     srv;
    dns_rdata_soa_t     soa;
    dns_rdata_txt_t     txt;
    dns_rdata_unknown_t unknown;
} dns_rdata_t;

// Whether (type, class) has its own member in dns_rdata_t.
bool
dns_rdata_known (dns_type_t type, dns_class_t class);

// Read the RDATA of len (RDLENGTH) octets at p->cur into *out and advance p->cur past it.
// DNS_ERR_TRUNCATED: the message ends within the RDATA.
// DNS_ERR_BAD_RDATA: the RDATA does not fit the type's format, or its fields do not fill
// exactly len octets.
// Names are checked like dns_name_from_bytes (pointer errors are passed on) and
// DNS_OK_NAME_TOO_LONG (an embedded name over DNS_NAME_MAX octets) is soft: *out is filled
// and p->cur advanced. On any other error p->cur and *out are unchanged.
dns_error_t
dns_rdata_a_from_bytes (dns_parser_t *p, size_t len, dns_rdata_a_t *out);
dns_error_t
dns_rdata_aaaa_from_bytes (dns_parser_t *p, size_t len, dns_rdata_aaaa_t *out);
dns_error_t
dns_rdata_ns_from_bytes (dns_parser_t *p, size_t len, dns_rdata_ns_t *out);
dns_error_t
dns_rdata_cname_from_bytes (dns_parser_t *p, size_t len, dns_rdata_cname_t *out);
dns_error_t
dns_rdata_ptr_from_bytes (dns_parser_t *p, size_t len, dns_rdata_ptr_t *out);
dns_error_t
dns_rdata_dname_from_bytes (dns_parser_t *p, size_t len, dns_rdata_dname_t *out);
dns_error_t
dns_rdata_mx_from_bytes (dns_parser_t *p, size_t len, dns_rdata_mx_t *out);
dns_error_t
dns_rdata_srv_from_bytes (dns_parser_t *p, size_t len, dns_rdata_srv_t *out);
dns_error_t
dns_rdata_soa_from_bytes (dns_parser_t *p, size_t len, dns_rdata_soa_t *out);
dns_error_t
dns_rdata_txt_from_bytes (dns_parser_t *p, size_t len, dns_rdata_txt_t *out);
dns_error_t
dns_rdata_unknown_from_bytes (dns_parser_t *p, size_t len, dns_rdata_unknown_t *out);

// Reads the RDATA into the dns_rdata_t member that (type, class) chooses (.unknown when
// !dns_rdata_known), as the functions above do.
dns_error_t
dns_rdata_from_bytes (
    dns_parser_t *p, dns_type_t type, dns_class_t class, size_t len, dns_rdata_t *out);

// Octets the RDATA takes in wire format.
size_t
dns_rdata_length (dns_type_t type, dns_class_t class, const dns_rdata_t *rdata);

// Write the RDATA (without RDLENGTH) at p->cur and advance p->cur past it. Names are copied as
// they are, compression pointers included. DNS_ERR_NO_SPACE (also when p->cur has already
// overflowed) leaves p->cur unchanged.
dns_error_t
dns_rdata_a_to_bytes (dns_parser_t *p, const dns_rdata_a_t *rdata);
dns_error_t
dns_rdata_aaaa_to_bytes (dns_parser_t *p, const dns_rdata_aaaa_t *rdata);
dns_error_t
dns_rdata_ns_to_bytes (dns_parser_t *p, const dns_rdata_ns_t *rdata);
dns_error_t
dns_rdata_cname_to_bytes (dns_parser_t *p, const dns_rdata_cname_t *rdata);
dns_error_t
dns_rdata_ptr_to_bytes (dns_parser_t *p, const dns_rdata_ptr_t *rdata);
dns_error_t
dns_rdata_dname_to_bytes (dns_parser_t *p, const dns_rdata_dname_t *rdata);
dns_error_t
dns_rdata_mx_to_bytes (dns_parser_t *p, const dns_rdata_mx_t *rdata);
dns_error_t
dns_rdata_srv_to_bytes (dns_parser_t *p, const dns_rdata_srv_t *rdata);
dns_error_t
dns_rdata_soa_to_bytes (dns_parser_t *p, const dns_rdata_soa_t *rdata);
dns_error_t
dns_rdata_txt_to_bytes (dns_parser_t *p, const dns_rdata_txt_t *rdata);
dns_error_t
dns_rdata_unknown_to_bytes (dns_parser_t *p, const dns_rdata_unknown_t *rdata);

// Writes the dns_rdata_t member that (type, class) chooses (.unknown when !dns_rdata_known),
// as the functions above do.
dns_error_t
dns_rdata_to_bytes (dns_parser_t *p, dns_type_t type, dns_class_t class, const dns_rdata_t *rdata);

// Writes the presentation form of the RDATA to buf; unknown types use the RFC 3597 form
// "\# <len> <hex>". Names are shown as they are (see dns_name_debug_r).
const char *
dns_rdata_display_r (
    dns_type_t type, dns_class_t class, const dns_rdata_t *rdata, char *buf, size_t len);

#endif
