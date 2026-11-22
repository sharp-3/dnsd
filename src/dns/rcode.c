#include <stdio.h>

#include "dns/rcode.h"

const char *
dns_rcode_display_r (dns_rcode_t value, char *buf, size_t len)
{
    switch (value)
    {
    case DNS_RCODE_NOERROR:
        return "NOERROR";
    case DNS_RCODE_FORMERR:
        return "FORMERR";
    case DNS_RCODE_SERVFAIL:
        return "SERVFAIL";
    case DNS_RCODE_NXDOMAIN:
        return "NXDOMAIN";
    case DNS_RCODE_NOTIMP:
        return "NOTIMP";
    case DNS_RCODE_REFUSED:
        return "REFUSED";
    case DNS_RCODE_YXDOMAIN:
        return "YXDOMAIN";
    case DNS_RCODE_YXRRSET:
        return "YXRRSET";
    case DNS_RCODE_NXRRSET:
        return "NXRRSET";
    case DNS_RCODE_NOTAUTH:
        return "NOTAUTH";
    case DNS_RCODE_NOTZONE:
        return "NOTZONE";
    case DNS_RCODE_DSOTYPENI:
        return "DSOTYPENI";
    default:
        snprintf (buf, len, "RCODE%d", value);
        return buf;
    }
}
