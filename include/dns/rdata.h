#ifndef DNSD_DNS_RDATA_H
#define DNSD_DNS_RDATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/params/class.h"
#include "dns/params/type.h"

#define DNS_RDATA_NAMES_MAX 2 // most domain names in one RDATA (SOA, MINFO)
#include "dns/rdata/a.h"
#include "dns/rdata/aaaa.h"
#include "dns/rdata/cname.h"
#include "dns/rdata/dname.h"
#include "dns/rdata/mb.h"
#include "dns/rdata/md.h"
#include "dns/rdata/mf.h"
#include "dns/rdata/mg.h"
#include "dns/rdata/minfo.h"
#include "dns/rdata/mr.h"
#include "dns/rdata/mx.h"
#include "dns/rdata/ns.h"
#include "dns/rdata/ptr.h"
#include "dns/rdata/soa.h"
#include "dns/rdata/srv.h"
#include "dns/rdata/txt.h"
#include "dns/rdata/unknown.h"

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
    dns_rdata_md_t      md;
    dns_rdata_mf_t      mf;
    dns_rdata_mb_t      mb;
    dns_rdata_mg_t      mg;
    dns_rdata_mr_t      mr;
    dns_rdata_minfo_t   minfo;
    dns_rdata_txt_t     txt;
    dns_rdata_unknown_t unknown;
} dns_rdata_t;

// type / class
bool
dns_rdata_known (dns_type_t type, dns_class_t class);

// dns_rdata_t <--> uint8_t * (wire format)
// len is RDLENGTH. Only TXT and unknown read by it; that the RDATA takes exactly len octets is
// checked by dns_record_from_bytes.
dns_error_t
dns_rdata_from_bytes (
    dns_cursor_t *p, dns_type_t type, dns_class_t class, size_t len, dns_rdata_t *out);
// With compress, compresses the names where RFC 3597 allows it (NS, CNAME, PTR, MX, SOA, MD,
// MF, MB, MG, MR, MINFO).
dns_error_t
dns_rdata_to_bytes (
    dns_cursor_t *p, dns_type_t type, dns_class_t class, const dns_rdata_t *rdata, bool compress);
size_t
dns_rdata_length (dns_type_t type, dns_class_t class, const dns_rdata_t *rdata);

// debug
const char *
dns_rdata_debug_r (
    dns_type_t type, dns_class_t class, const dns_rdata_t *rdata, char *buf, size_t len);

#endif
