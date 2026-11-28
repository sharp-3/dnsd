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

dns_error_t
dns_rcode_from_string (dns_rcode_t *self, const char *str)
{
    uint32_t value;
    if (!params_from_string (&table, str, &value)) return DNS_ERR_BAD_TEXT;
    *self = (dns_rcode_t)value;
    return DNS_OK;
}

dns_error_t
dns_rcode_to_string (dns_rcode_t self, GString *gs)
{
    params_to_string (&table, self, gs);
    return DNS_OK;
}
