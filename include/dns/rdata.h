#ifndef DNSD_DNS_RDATA_H
#define DNSD_DNS_RDATA_H

#include <stddef.h>
#include <stdint.h>

#include "dns/error.h"
#include "dns/params/class.h"
#include "dns/params/type.h"
#include "dns/parser.h"
#include "dns/rdata/a.h"
#include "dns/rdata/aaaa.h"
#include "dns/rdata/cname.h"
#include "dns/rdata/dname.h"
#include "dns/rdata/mx.h"
#include "dns/rdata/ns.h"
#include "dns/rdata/ptr.h"
#include "dns/rdata/soa.h"
#include "dns/rdata/srv.h"
#include "dns/rdata/txt.h"
#include "dns/rdata/unknown.h"

// Each RR type has its own header under dns/rdata/ with its RDATA struct and
// dns_rdata_<type>_from_bytes / dns_rdata_<type>_to_bytes. Names in them are in wire format
// and may end with a compression pointer; they point into the message the RDATA was read from.
//
// dns_rdata_<type>_from_bytes reads the RDATA of len (RDLENGTH) octets at p->cur into *out and
// advances p->cur past it.
// DNS_ERR_TRUNCATED: the message ends within the RDATA.
// DNS_ERR_BAD_RDATA: the RDATA does not fit the type's format, or its fields do not fill
// exactly len octets.
// Names are checked like dns_name_from_bytes (pointer errors are passed on) and
// DNS_OK_NAME_TOO_LONG (an embedded name over DNS_NAME_MAX octets) is soft: *out is filled
// and p->cur advanced. On any other error p->cur and *out are unchanged.
//
// dns_rdata_<type>_to_bytes writes the RDATA (without RDLENGTH) at p->cur and advances p->cur
// past it. Names are copied as they are, compression pointers included. DNS_ERR_NO_SPACE (also
// when p->cur has already overflowed) leaves p->cur unchanged.

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

// Reads the RDATA into the dns_rdata_t member that (type, class) chooses (.unknown when
// !dns_rdata_known), as dns_rdata_<type>_from_bytes does.
dns_error_t
dns_rdata_from_bytes (
    dns_parser_t *p, dns_type_t type, dns_class_t class, size_t len, dns_rdata_t *out);

// Octets the RDATA takes in wire format.
size_t
dns_rdata_length (dns_type_t type, dns_class_t class, const dns_rdata_t *rdata);

// Writes the dns_rdata_t member that (type, class) chooses (.unknown when !dns_rdata_known),
// as dns_rdata_<type>_to_bytes does.
dns_error_t
dns_rdata_to_bytes (dns_parser_t *p, dns_type_t type, dns_class_t class, const dns_rdata_t *rdata);

// Writes the presentation form of the RDATA to buf; unknown types use the RFC 3597 form
// "\# <len> <hex>". Names are shown as they are (see dns_name_debug_r).
const char *
dns_rdata_display_r (
    dns_type_t type, dns_class_t class, const dns_rdata_t *rdata, char *buf, size_t len);

#endif
