#include "dns/params/class.h"
#include "common.h"

static const params_name_t names[] = {
    {DNS_CLASS_IN, "IN"},
    {DNS_CLASS_CH, "CH"},
    {DNS_CLASS_HS, "HS"},
    {DNS_CLASS_NONE, "NONE"},
    {DNS_CLASS_ANY, "ANY"},
};

static const params_table_t table = PARAMS_TABLE (names, "CLASS", UINT16_MAX);

bool
dns_class_is_reserved (dns_class_t class)
{
    return class == 0 || class == 0xFFFF;
}

bool
dns_class_is_qonly_or_meta (dns_class_t class)
{
    return (class >= 0x0080 && class <= 0x00FF) || (class >= 0xE000 && class <= 0xFEFF);
}

bool
dns_class_is_data (dns_class_t class)
{
    return !dns_class_is_reserved (class) && !dns_class_is_qonly_or_meta (class);
}

const char *
dns_class_display_r (dns_class_t value, char *buf, size_t len)
{
    return params_display_r (&table, value, buf, len);
}

dns_error_t
dns_class_from_string (const char *str, dns_class_t *out)
{
    uint32_t value;
    if (!params_from_string (&table, str, &value)) return DNS_ERR_BAD_TEXT;
    *out = (dns_class_t)value;
    return DNS_OK;
}
