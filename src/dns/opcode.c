#include <stdio.h>

#include "dns/opcode.h"

const char *
dns_opcode_display_r (dns_opcode_t value, char *buf, size_t len)
{
    switch (value)
    {
    case DNS_OPCODE_QUERY:
        return "QUERY";
    case DNS_OPCODE_IQUERY:
        return "IQUERY";
    case DNS_OPCODE_STATUS:
        return "STATUS";
    case DNS_OPCODE_NOTIFY:
        return "NOTIFY";
    case DNS_OPCODE_UPDATE:
        return "UPDATE";
    case DNS_OPCODE_DSO:
        return "DSO";
    default:
        snprintf (buf, len, "OPCODE%d", value);
        return buf;
    }
}
