#include "dns/params/rcode.h"
#include "common.h"

static const params_name_t names[] = {
    {DNS_RCODE_NOERROR, "NOERROR"},
    {DNS_RCODE_FORMERR, "FORMERR"},
    {DNS_RCODE_SERVFAIL, "SERVFAIL"},
    {DNS_RCODE_NXDOMAIN, "NXDOMAIN"},
    {DNS_RCODE_NOTIMP, "NOTIMP"},
    {DNS_RCODE_REFUSED, "REFUSED"},
    {DNS_RCODE_YXDOMAIN, "YXDOMAIN"},
    {DNS_RCODE_YXRRSET, "YXRRSET"},
    {DNS_RCODE_NXRRSET, "NXRRSET"},
    {DNS_RCODE_NOTAUTH, "NOTAUTH"},
    {DNS_RCODE_NOTZONE, "NOTZONE"},
    {DNS_RCODE_DSOTYPENI, "DSOTYPENI"},
};

static const params_table_t table = PARAMS_TABLE (names, "RCODE", DNS_RCODE_MAX);

const char *
dns_rcode_display_r (dns_rcode_t value, char *buf, size_t len)
{
    return params_display_r (&table, value, buf, len);
}

dns_error_t
dns_rcode_from_string (const char *str, dns_rcode_t *out)
{
    uint32_t value;
    if (!params_from_string (&table, str, &value)) return DNS_ERR_BAD_TEXT;
    *out = (dns_rcode_t)value;
    return DNS_OK;
}
