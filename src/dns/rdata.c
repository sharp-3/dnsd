#include "dns/rdata.h"
#include "rdata/common.h"

bool
dns_rdata_known (dns_type_t type, dns_class_t class)
{
    switch (type)
    {
    case DNS_TYPE_A:
    case DNS_TYPE_AAAA:
        return class == DNS_CLASS_IN;
    case DNS_TYPE_NS:
    case DNS_TYPE_CNAME:
    case DNS_TYPE_PTR:
    case DNS_TYPE_DNAME:
    case DNS_TYPE_MX:
    case DNS_TYPE_SRV:
    case DNS_TYPE_SOA:
    case DNS_TYPE_TXT:
        return true;
    default:
        return false;
    }
}

dns_error_t
dns_rdata_expand (const dns_cursor_t *p,
                  dns_type_t          type,
                  dns_class_t         class,
                  const dns_rdata_t  *rdata,
                  uint8_t            *buf,
                  size_t              len,
                  dns_rdata_t        *out)
{
    if (!dns_rdata_known (type, class))
        return dns_rdata_unknown_expand (p, &rdata->unknown, buf, len, &out->unknown);

    switch (type)
    {
    case DNS_TYPE_A:
        return dns_rdata_a_expand (p, &rdata->a, buf, len, &out->a);
    case DNS_TYPE_AAAA:
        return dns_rdata_aaaa_expand (p, &rdata->aaaa, buf, len, &out->aaaa);
    case DNS_TYPE_NS:
        return dns_rdata_ns_expand (p, &rdata->ns, buf, len, &out->ns);
    case DNS_TYPE_CNAME:
        return dns_rdata_cname_expand (p, &rdata->cname, buf, len, &out->cname);
    case DNS_TYPE_PTR:
        return dns_rdata_ptr_expand (p, &rdata->ptr, buf, len, &out->ptr);
    case DNS_TYPE_DNAME:
        return dns_rdata_dname_expand (p, &rdata->dname, buf, len, &out->dname);
    case DNS_TYPE_MX:
        return dns_rdata_mx_expand (p, &rdata->mx, buf, len, &out->mx);
    case DNS_TYPE_SRV:
        return dns_rdata_srv_expand (p, &rdata->srv, buf, len, &out->srv);
    case DNS_TYPE_SOA:
        return dns_rdata_soa_expand (p, &rdata->soa, buf, len, &out->soa);
    case DNS_TYPE_TXT:
        return dns_rdata_txt_expand (p, &rdata->txt, buf, len, &out->txt);
    default:
        return dns_rdata_unknown_expand (p, &rdata->unknown, buf, len, &out->unknown);
    }
}

dns_error_t
dns_rdata_compress (const dns_cursor_t *p,
                    dns_type_t          type,
                    dns_class_t         class,
                    const dns_rdata_t  *rdata,
                    uint8_t            *buf,
                    size_t              len,
                    dns_rdata_t        *out)
{
    if (!dns_rdata_known (type, class))
        return dns_rdata_unknown_compress (p, &rdata->unknown, buf, len, &out->unknown);

    switch (type)
    {
    case DNS_TYPE_A:
        return dns_rdata_a_compress (p, &rdata->a, buf, len, &out->a);
    case DNS_TYPE_AAAA:
        return dns_rdata_aaaa_compress (p, &rdata->aaaa, buf, len, &out->aaaa);
    case DNS_TYPE_NS:
        return dns_rdata_ns_compress (p, &rdata->ns, buf, len, &out->ns);
    case DNS_TYPE_CNAME:
        return dns_rdata_cname_compress (p, &rdata->cname, buf, len, &out->cname);
    case DNS_TYPE_PTR:
        return dns_rdata_ptr_compress (p, &rdata->ptr, buf, len, &out->ptr);
    case DNS_TYPE_DNAME:
        return dns_rdata_dname_compress (p, &rdata->dname, buf, len, &out->dname);
    case DNS_TYPE_MX:
        return dns_rdata_mx_compress (p, &rdata->mx, buf, len, &out->mx);
    case DNS_TYPE_SRV:
        return dns_rdata_srv_compress (p, &rdata->srv, buf, len, &out->srv);
    case DNS_TYPE_SOA:
        return dns_rdata_soa_compress (p, &rdata->soa, buf, len, &out->soa);
    case DNS_TYPE_TXT:
        return dns_rdata_txt_compress (p, &rdata->txt, buf, len, &out->txt);
    default:
        return dns_rdata_unknown_compress (p, &rdata->unknown, buf, len, &out->unknown);
    }
}

dns_error_t
dns_rdata_from_bytes (
    dns_cursor_t *p, dns_type_t type, dns_class_t class, size_t len, dns_rdata_t *out)
{
    if (!dns_rdata_known (type, class)) return dns_rdata_unknown_from_bytes (p, len, &out->unknown);

    switch (type)
    {
    case DNS_TYPE_A:
        return dns_rdata_a_from_bytes (p, len, &out->a);
    case DNS_TYPE_AAAA:
        return dns_rdata_aaaa_from_bytes (p, len, &out->aaaa);
    case DNS_TYPE_NS:
        return dns_rdata_ns_from_bytes (p, len, &out->ns);
    case DNS_TYPE_CNAME:
        return dns_rdata_cname_from_bytes (p, len, &out->cname);
    case DNS_TYPE_PTR:
        return dns_rdata_ptr_from_bytes (p, len, &out->ptr);
    case DNS_TYPE_DNAME:
        return dns_rdata_dname_from_bytes (p, len, &out->dname);
    case DNS_TYPE_MX:
        return dns_rdata_mx_from_bytes (p, len, &out->mx);
    case DNS_TYPE_SRV:
        return dns_rdata_srv_from_bytes (p, len, &out->srv);
    case DNS_TYPE_SOA:
        return dns_rdata_soa_from_bytes (p, len, &out->soa);
    case DNS_TYPE_TXT:
        return dns_rdata_txt_from_bytes (p, len, &out->txt);
    default:
        return dns_rdata_unknown_from_bytes (p, len, &out->unknown);
    }
}

size_t
dns_rdata_length (dns_type_t type, dns_class_t class, const dns_rdata_t *rd)
{
    if (!dns_rdata_known (type, class)) return dns_rdata_unknown_length (&rd->unknown);

    switch (type)
    {
    case DNS_TYPE_A:
        return dns_rdata_a_length (&rd->a);
    case DNS_TYPE_AAAA:
        return dns_rdata_aaaa_length (&rd->aaaa);
    case DNS_TYPE_NS:
        return dns_rdata_ns_length (&rd->ns);
    case DNS_TYPE_CNAME:
        return dns_rdata_cname_length (&rd->cname);
    case DNS_TYPE_PTR:
        return dns_rdata_ptr_length (&rd->ptr);
    case DNS_TYPE_DNAME:
        return dns_rdata_dname_length (&rd->dname);
    case DNS_TYPE_MX:
        return dns_rdata_mx_length (&rd->mx);
    case DNS_TYPE_SRV:
        return dns_rdata_srv_length (&rd->srv);
    case DNS_TYPE_SOA:
        return dns_rdata_soa_length (&rd->soa);
    case DNS_TYPE_TXT:
        return dns_rdata_txt_length (&rd->txt);
    default:
        return dns_rdata_unknown_length (&rd->unknown);
    }
}

dns_error_t
dns_rdata_to_bytes (dns_cursor_t *p, dns_type_t type, dns_class_t class, const dns_rdata_t *rd)
{
    if (!dns_rdata_known (type, class)) return dns_rdata_unknown_to_bytes (p, &rd->unknown);

    switch (type)
    {
    case DNS_TYPE_A:
        return dns_rdata_a_to_bytes (p, &rd->a);
    case DNS_TYPE_AAAA:
        return dns_rdata_aaaa_to_bytes (p, &rd->aaaa);
    case DNS_TYPE_NS:
        return dns_rdata_ns_to_bytes (p, &rd->ns);
    case DNS_TYPE_CNAME:
        return dns_rdata_cname_to_bytes (p, &rd->cname);
    case DNS_TYPE_PTR:
        return dns_rdata_ptr_to_bytes (p, &rd->ptr);
    case DNS_TYPE_DNAME:
        return dns_rdata_dname_to_bytes (p, &rd->dname);
    case DNS_TYPE_MX:
        return dns_rdata_mx_to_bytes (p, &rd->mx);
    case DNS_TYPE_SRV:
        return dns_rdata_srv_to_bytes (p, &rd->srv);
    case DNS_TYPE_SOA:
        return dns_rdata_soa_to_bytes (p, &rd->soa);
    case DNS_TYPE_TXT:
        return dns_rdata_txt_to_bytes (p, &rd->txt);
    default:
        return dns_rdata_unknown_to_bytes (p, &rd->unknown);
    }
}

const char *
dns_rdata_display_r (
    dns_type_t type, dns_class_t class, const dns_rdata_t *rd, char *buf, size_t len)
{
    if (len == 0) return buf;

    if (!dns_rdata_known (type, class))
    {
        rdata_unknown_display (&rd->unknown, buf, len);
        return buf;
    }

    switch (type)
    {
    case DNS_TYPE_A:
        rdata_a_display (&rd->a, buf, len);
        break;
    case DNS_TYPE_AAAA:
        rdata_aaaa_display (&rd->aaaa, buf, len);
        break;
    case DNS_TYPE_NS:
        rdata_ns_display (&rd->ns, buf, len);
        break;
    case DNS_TYPE_CNAME:
        rdata_cname_display (&rd->cname, buf, len);
        break;
    case DNS_TYPE_PTR:
        rdata_ptr_display (&rd->ptr, buf, len);
        break;
    case DNS_TYPE_DNAME:
        rdata_dname_display (&rd->dname, buf, len);
        break;
    case DNS_TYPE_MX:
        rdata_mx_display (&rd->mx, buf, len);
        break;
    case DNS_TYPE_SRV:
        rdata_srv_display (&rd->srv, buf, len);
        break;
    case DNS_TYPE_SOA:
        rdata_soa_display (&rd->soa, buf, len);
        break;
    case DNS_TYPE_TXT:
        rdata_txt_display (&rd->txt, buf, len);
        break;
    default:
        rdata_unknown_display (&rd->unknown, buf, len);
        break;
    }
    return buf;
}
