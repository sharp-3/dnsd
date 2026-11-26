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
    return class == DNS_CLASS_RESERVED_LOW || class == DNS_CLASS_RESERVED_HIGH;
}

bool
dns_class_is_qonly_or_meta (dns_class_t class)
{
    return (DNS_CLASS_QONLY_OR_META_LOW_MIN <= class && class <= DNS_CLASS_QONLY_OR_META_LOW_MAX) ||
           (DNS_CLASS_QONLY_OR_META_HIGH_MIN <= class && class <= DNS_CLASS_QONLY_OR_META_HIGH_MAX);
}

bool
dns_class_is_data (dns_class_t class)
{
    return (DNS_CLASS_DATA_LOW_MIN <= class && class <= DNS_CLASS_DATA_LOW_MAX) ||
           (DNS_CLASS_DATA_MID_MIN <= class && class <= DNS_CLASS_DATA_MID_MAX) ||
           (DNS_CLASS_DATA_HIGH_MIN <= class && class <= DNS_CLASS_DATA_HIGH_MAX);
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
