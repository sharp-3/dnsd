#include <stdio.h>

#include "common.h"
#include "dns/params/rcode.h"

static const struct
{
    dns_rcode_t value;
    const char *name;
} names[] = {
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

const char *
dns_rcode_display_r (dns_rcode_t value, char *buf, size_t len)
{
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (names[i].value == value) return names[i].name;
    snprintf (buf, len, "RCODE%d", value);
    return buf;
}

dns_error_t
dns_rcode_from_string (const char *str, dns_rcode_t *out)
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
    if (!params_generic_from_string (str, "RCODE", DNS_RCODE_MAX, &value)) return DNS_ERR_BAD_TEXT;
    *out = (dns_rcode_t)value;
    return DNS_OK;
}
