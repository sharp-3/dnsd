#include <stdio.h>

#include "common.h"
#include "dns/params/class.h"

static const struct
{
    dns_class_t value;
    const char *name;
} names[] = {
    {DNS_CLASS_IN, "IN"},
    {DNS_CLASS_CH, "CH"},
    {DNS_CLASS_HS, "HS"},
    {DNS_CLASS_NONE, "NONE"},
    {DNS_CLASS_ANY, "ANY"},
};

const char *
dns_class_display_r (dns_class_t value, char *buf, size_t len)
{
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (names[i].value == value) return names[i].name;
    snprintf (buf, len, "CLASS%d", value);
    return buf;
}

dns_error_t
dns_class_from_string (const char *str, dns_class_t *out)
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
    if (!params_generic_from_string (str, "CLASS", UINT16_MAX, &value)) return DNS_ERR_BAD_TEXT;
    *out = (dns_class_t)value;
    return DNS_OK;
}
