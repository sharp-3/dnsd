#include <stdio.h>

#include "common.h"
#include "dns/params/type.h"

static const struct
{
    dns_type_t  value;
    const char *name;
} names[] = {
    {DNS_TYPE_A, "A"},         {DNS_TYPE_NS, "NS"},
    {DNS_TYPE_CNAME, "CNAME"}, {DNS_TYPE_SOA, "SOA"},
    {DNS_TYPE_PTR, "PTR"},     {DNS_TYPE_HINFO, "HINFO"},
    {DNS_TYPE_MX, "MX"},       {DNS_TYPE_TXT, "TXT"},
    {DNS_TYPE_AAAA, "AAAA"},   {DNS_TYPE_SRV, "SRV"},
    {DNS_TYPE_NAPTR, "NAPTR"}, {DNS_TYPE_DNAME, "DNAME"},
    {DNS_TYPE_OPT, "OPT"},     {DNS_TYPE_DS, "DS"},
    {DNS_TYPE_SSHFP, "SSHFP"}, {DNS_TYPE_RRSIG, "RRSIG"},
    {DNS_TYPE_NSEC, "NSEC"},   {DNS_TYPE_DNSKEY, "DNSKEY"},
    {DNS_TYPE_NSEC3, "NSEC3"}, {DNS_TYPE_NSEC3PARAM, "NSEC3PARAM"},
    {DNS_TYPE_TLSA, "TLSA"},   {DNS_TYPE_SVCB, "SVCB"},
    {DNS_TYPE_HTTPS, "HTTPS"}, {DNS_TYPE_IXFR, "IXFR"},
    {DNS_TYPE_AXFR, "AXFR"},   {DNS_TYPE_ANY, "ANY"},
    {DNS_TYPE_CAA, "CAA"},
};

const char *
dns_type_display_r (dns_type_t value, char *buf, size_t len)
{
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (names[i].value == value) return names[i].name;
    snprintf (buf, len, "TYPE%d", value);
    return buf;
}

dns_error_t
dns_type_from_string (const char *str, dns_type_t *out)
{
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
    {
        if (params_equal (str, names[i].name))
        {
            *out = names[i].value;
            return DNS_OK;
        }
    }

    uint32_t value;
    if (!params_generic_from_string (str, "TYPE", UINT16_MAX, &value)) return DNS_ERR_BAD_TEXT;
    *out = (dns_type_t)value;
    return DNS_OK;
}
