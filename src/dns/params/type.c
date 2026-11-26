#include "dns/params/type.h"
#include "common.h"

static const params_name_t names[] = {
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

static const params_table_t table = PARAMS_TABLE (names, "TYPE", UINT16_MAX);

bool
dns_type_is_reserved (dns_type_t type)
{
    return type == DNS_TYPE_RESERVED_LOW ||
           (DNS_TYPE_RESERVED_MID_MIN <= type && type <= DNS_TYPE_RESERVED_MID_MAX) ||
           type == DNS_TYPE_RESERVED_HIGH;
}

bool
dns_type_is_qonly_or_meta (dns_type_t type)
{
    return (DNS_TYPE_QONLY_OR_META_MIN <= type && type <= DNS_TYPE_QONLY_OR_META_MAX) ||
           type == DNS_TYPE_OPT;
}

bool
dns_type_is_data (dns_type_t type)
{
    return (DNS_TYPE_DATA_LOW_MIN <= type && type <= DNS_TYPE_DATA_LOW_MAX &&
            type != DNS_TYPE_OPT) ||
           (DNS_TYPE_DATA_MID_MIN <= type && type <= DNS_TYPE_DATA_MID_MAX) ||
           (DNS_TYPE_DATA_HIGH_MIN <= type && type <= DNS_TYPE_DATA_HIGH_MAX);
}

const char *
dns_type_display_r (dns_type_t value, char *buf, size_t len)
{
    return params_display_r (&table, value, buf, len);
}

dns_error_t
dns_type_from_string (const char *str, dns_type_t *out)
{
    uint32_t value;
    if (!params_from_string (&table, str, &value)) return DNS_ERR_BAD_TEXT;
    *out = (dns_type_t)value;
    return DNS_OK;
}
