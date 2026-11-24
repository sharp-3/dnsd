#include <stdio.h>

#include "common.h"
#include "dns/params/opcode.h"

static const struct
{
    dns_opcode_t value;
    const char  *name;
} names[] = {
    {DNS_OPCODE_QUERY, "QUERY"},
    {DNS_OPCODE_IQUERY, "IQUERY"},
    {DNS_OPCODE_STATUS, "STATUS"},
    {DNS_OPCODE_NOTIFY, "NOTIFY"},
    {DNS_OPCODE_UPDATE, "UPDATE"},
    {DNS_OPCODE_DSO, "DSO"},
};

const char *
dns_opcode_display_r (dns_opcode_t value, char *buf, size_t len)
{
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (names[i].value == value) return names[i].name;
    snprintf (buf, len, "OPCODE%d", value);
    return buf;
}

dns_error_t
dns_opcode_from_string (const char *str, dns_opcode_t *out)
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
    if (!params_generic_from_string (str, "OPCODE", DNS_OPCODE_MAX, &value))
        return DNS_ERR_BAD_TEXT;
    *out = (dns_opcode_t)value;
    return DNS_OK;
}
