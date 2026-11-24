#include "dns/params/opcode.h"
#include "common.h"

static const params_name_t names[] = {
    {DNS_OPCODE_QUERY, "QUERY"},
    {DNS_OPCODE_IQUERY, "IQUERY"},
    {DNS_OPCODE_STATUS, "STATUS"},
    {DNS_OPCODE_NOTIFY, "NOTIFY"},
    {DNS_OPCODE_UPDATE, "UPDATE"},
    {DNS_OPCODE_DSO, "DSO"},
};

static const params_table_t table = PARAMS_TABLE (names, "OPCODE", DNS_OPCODE_MAX);

const char *
dns_opcode_display_r (dns_opcode_t value, char *buf, size_t len)
{
    return params_display_r (&table, value, buf, len);
}

dns_error_t
dns_opcode_from_string (const char *str, dns_opcode_t *out)
{
    uint32_t value;
    if (!params_from_string (&table, str, &value)) return DNS_ERR_BAD_TEXT;
    *out = (dns_opcode_t)value;
    return DNS_OK;
}
