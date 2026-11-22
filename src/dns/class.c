#include <stdio.h>

#include "dns/class.h"

const char *
dns_class_display_r (dns_class_t value, char *buf, size_t len)
{
    switch (value)
    {
    case DNS_CLASS_IN:
        return "IN";
    case DNS_CLASS_CH:
        return "CH";
    case DNS_CLASS_HS:
        return "HS";
    case DNS_CLASS_NONE:
        return "NONE";
    case DNS_CLASS_ANY:
        return "ANY";
    default:
        snprintf (buf, len, "CLASS%d", value);
        return buf;
    }
}
