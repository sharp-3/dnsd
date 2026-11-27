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
    case DNS_TYPE_MD:
    case DNS_TYPE_MF:
    case DNS_TYPE_MB:
    case DNS_TYPE_MG:
    case DNS_TYPE_MR:
    case DNS_TYPE_MINFO:
    case DNS_TYPE_TXT:
        return true;
    default:
        return false;
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
    case DNS_TYPE_MD:
        return dns_rdata_md_from_bytes (p, len, &out->md);
    case DNS_TYPE_MF:
        return dns_rdata_mf_from_bytes (p, len, &out->mf);
    case DNS_TYPE_MB:
        return dns_rdata_mb_from_bytes (p, len, &out->mb);
    case DNS_TYPE_MG:
        return dns_rdata_mg_from_bytes (p, len, &out->mg);
    case DNS_TYPE_MR:
        return dns_rdata_mr_from_bytes (p, len, &out->mr);
    case DNS_TYPE_MINFO:
        return dns_rdata_minfo_from_bytes (p, len, &out->minfo);
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
    case DNS_TYPE_MD:
        return dns_rdata_md_length (&rd->md);
    case DNS_TYPE_MF:
        return dns_rdata_mf_length (&rd->mf);
    case DNS_TYPE_MB:
        return dns_rdata_mb_length (&rd->mb);
    case DNS_TYPE_MG:
        return dns_rdata_mg_length (&rd->mg);
    case DNS_TYPE_MR:
        return dns_rdata_mr_length (&rd->mr);
    case DNS_TYPE_MINFO:
        return dns_rdata_minfo_length (&rd->minfo);
    case DNS_TYPE_TXT:
        return dns_rdata_txt_length (&rd->txt);
    default:
        return dns_rdata_unknown_length (&rd->unknown);
    }
}

dns_error_t
dns_rdata_to_bytes (
    dns_cursor_t *p, dns_type_t type, dns_class_t class, const dns_rdata_t *rd, bool compress)
{
    if (!dns_rdata_known (type, class))
        return dns_rdata_unknown_to_bytes (p, &rd->unknown, compress);

    switch (type)
    {
    case DNS_TYPE_A:
        return dns_rdata_a_to_bytes (p, &rd->a, compress);
    case DNS_TYPE_AAAA:
        return dns_rdata_aaaa_to_bytes (p, &rd->aaaa, compress);
    case DNS_TYPE_NS:
        return dns_rdata_ns_to_bytes (p, &rd->ns, compress);
    case DNS_TYPE_CNAME:
        return dns_rdata_cname_to_bytes (p, &rd->cname, compress);
    case DNS_TYPE_PTR:
        return dns_rdata_ptr_to_bytes (p, &rd->ptr, compress);
    case DNS_TYPE_DNAME:
        return dns_rdata_dname_to_bytes (p, &rd->dname, compress);
    case DNS_TYPE_MX:
        return dns_rdata_mx_to_bytes (p, &rd->mx, compress);
    case DNS_TYPE_SRV:
        return dns_rdata_srv_to_bytes (p, &rd->srv, compress);
    case DNS_TYPE_SOA:
        return dns_rdata_soa_to_bytes (p, &rd->soa, compress);
    case DNS_TYPE_MD:
        return dns_rdata_md_to_bytes (p, &rd->md, compress);
    case DNS_TYPE_MF:
        return dns_rdata_mf_to_bytes (p, &rd->mf, compress);
    case DNS_TYPE_MB:
        return dns_rdata_mb_to_bytes (p, &rd->mb, compress);
    case DNS_TYPE_MG:
        return dns_rdata_mg_to_bytes (p, &rd->mg, compress);
    case DNS_TYPE_MR:
        return dns_rdata_mr_to_bytes (p, &rd->mr, compress);
    case DNS_TYPE_MINFO:
        return dns_rdata_minfo_to_bytes (p, &rd->minfo, compress);
    case DNS_TYPE_TXT:
        return dns_rdata_txt_to_bytes (p, &rd->txt, compress);
    default:
        return dns_rdata_unknown_to_bytes (p, &rd->unknown, compress);
    }
}

const char *
dns_rdata_debug_r (dns_type_t type, dns_class_t class, const dns_rdata_t *rd, char *buf, size_t len)
{
    if (len == 0) return buf;

    if (!dns_rdata_known (type, class))
    {
        rdata_unknown_debug (&rd->unknown, buf, len);
        return buf;
    }

    switch (type)
    {
    case DNS_TYPE_A:
        rdata_a_debug (&rd->a, buf, len);
        break;
    case DNS_TYPE_AAAA:
        rdata_aaaa_debug (&rd->aaaa, buf, len);
        break;
    case DNS_TYPE_NS:
        rdata_ns_debug (&rd->ns, buf, len);
        break;
    case DNS_TYPE_CNAME:
        rdata_cname_debug (&rd->cname, buf, len);
        break;
    case DNS_TYPE_PTR:
        rdata_ptr_debug (&rd->ptr, buf, len);
        break;
    case DNS_TYPE_DNAME:
        rdata_dname_debug (&rd->dname, buf, len);
        break;
    case DNS_TYPE_MX:
        rdata_mx_debug (&rd->mx, buf, len);
        break;
    case DNS_TYPE_SRV:
        rdata_srv_debug (&rd->srv, buf, len);
        break;
    case DNS_TYPE_SOA:
        rdata_soa_debug (&rd->soa, buf, len);
        break;
    case DNS_TYPE_MD:
        rdata_md_debug (&rd->md, buf, len);
        break;
    case DNS_TYPE_MF:
        rdata_mf_debug (&rd->mf, buf, len);
        break;
    case DNS_TYPE_MB:
        rdata_mb_debug (&rd->mb, buf, len);
        break;
    case DNS_TYPE_MG:
        rdata_mg_debug (&rd->mg, buf, len);
        break;
    case DNS_TYPE_MR:
        rdata_mr_debug (&rd->mr, buf, len);
        break;
    case DNS_TYPE_MINFO:
        rdata_minfo_debug (&rd->minfo, buf, len);
        break;
    case DNS_TYPE_TXT:
        rdata_txt_debug (&rd->txt, buf, len);
        break;
    default:
        rdata_unknown_debug (&rd->unknown, buf, len);
        break;
    }
    return buf;
}
