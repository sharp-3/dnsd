#include <stdio.h>

#include "dns/type.h"

const char *
dns_type_display_r (dns_type_t value, char *buf, size_t len)
{
    switch (value)
    {
    case DNS_TYPE_A:
        return "A";
    case DNS_TYPE_NS:
        return "NS";
    case DNS_TYPE_CNAME:
        return "CNAME";
    case DNS_TYPE_SOA:
        return "SOA";
    case DNS_TYPE_PTR:
        return "PTR";
    case DNS_TYPE_HINFO:
        return "HINFO";
    case DNS_TYPE_MX:
        return "MX";
    case DNS_TYPE_TXT:
        return "TXT";
    case DNS_TYPE_AAAA:
        return "AAAA";
    case DNS_TYPE_SRV:
        return "SRV";
    case DNS_TYPE_NAPTR:
        return "NAPTR";
    case DNS_TYPE_DNAME:
        return "DNAME";
    case DNS_TYPE_OPT:
        return "OPT";
    case DNS_TYPE_DS:
        return "DS";
    case DNS_TYPE_SSHFP:
        return "SSHFP";
    case DNS_TYPE_RRSIG:
        return "RRSIG";
    case DNS_TYPE_NSEC:
        return "NSEC";
    case DNS_TYPE_DNSKEY:
        return "DNSKEY";
    case DNS_TYPE_NSEC3:
        return "NSEC3";
    case DNS_TYPE_NSEC3PARAM:
        return "NSEC3PARAM";
    case DNS_TYPE_TLSA:
        return "TLSA";
    case DNS_TYPE_SVCB:
        return "SVCB";
    case DNS_TYPE_HTTPS:
        return "HTTPS";
    case DNS_TYPE_IXFR:
        return "IXFR";
    case DNS_TYPE_AXFR:
        return "AXFR";
    case DNS_TYPE_ANY:
        return "ANY";
    case DNS_TYPE_CAA:
        return "CAA";
    default:
        snprintf (buf, len, "TYPE%d", value);
        return buf;
    }
}
