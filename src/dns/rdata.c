#include "dns/rdata.h"
#include "rdata/common.h"

bool
dns_rdata_known (dns_type_t type, dns_class_t class)
{
    switch (type)
    {
    case DNS_TYPE_A:
    case DNS_TYPE_AAAA:
        return DNS_CLASS_IN == class;
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
dns_rdata_from_wire (
    dns_cursor_t *p, dns_type_t type, dns_class_t class, size_t len, dns_rdata_t *out)
{
    if (!dns_rdata_known (type, class)) return dns_rdata_unknown_from_wire (p, len, &out->unknown);

    switch (type)
    {
    case DNS_TYPE_A:
        return dns_rdata_a_from_wire (p, len, &out->a);
    case DNS_TYPE_AAAA:
        return dns_rdata_aaaa_from_wire (p, len, &out->aaaa);
    case DNS_TYPE_NS:
        return dns_rdata_ns_from_wire (p, len, &out->ns);
    case DNS_TYPE_CNAME:
        return dns_rdata_cname_from_wire (p, len, &out->cname);
    case DNS_TYPE_PTR:
        return dns_rdata_ptr_from_wire (p, len, &out->ptr);
    case DNS_TYPE_DNAME:
        return dns_rdata_dname_from_wire (p, len, &out->dname);
    case DNS_TYPE_MX:
        return dns_rdata_mx_from_wire (p, len, &out->mx);
    case DNS_TYPE_SRV:
        return dns_rdata_srv_from_wire (p, len, &out->srv);
    case DNS_TYPE_SOA:
        return dns_rdata_soa_from_wire (p, len, &out->soa);
    case DNS_TYPE_MD:
        return dns_rdata_md_from_wire (p, len, &out->md);
    case DNS_TYPE_MF:
        return dns_rdata_mf_from_wire (p, len, &out->mf);
    case DNS_TYPE_MB:
        return dns_rdata_mb_from_wire (p, len, &out->mb);
    case DNS_TYPE_MG:
        return dns_rdata_mg_from_wire (p, len, &out->mg);
    case DNS_TYPE_MR:
        return dns_rdata_mr_from_wire (p, len, &out->mr);
    case DNS_TYPE_MINFO:
        return dns_rdata_minfo_from_wire (p, len, &out->minfo);
    case DNS_TYPE_TXT:
        return dns_rdata_txt_from_wire (p, len, &out->txt);
    default:
        return dns_rdata_unknown_from_wire (p, len, &out->unknown);
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
dns_rdata_to_wire (
    dns_cursor_t *p, dns_type_t type, dns_class_t class, const dns_rdata_t *rd, bool compress)
{
    if (!dns_rdata_known (type, class))
        return dns_rdata_unknown_to_wire (p, &rd->unknown, compress);

    switch (type)
    {
    case DNS_TYPE_A:
        return dns_rdata_a_to_wire (p, &rd->a, compress);
    case DNS_TYPE_AAAA:
        return dns_rdata_aaaa_to_wire (p, &rd->aaaa, compress);
    case DNS_TYPE_NS:
        return dns_rdata_ns_to_wire (p, &rd->ns, compress);
    case DNS_TYPE_CNAME:
        return dns_rdata_cname_to_wire (p, &rd->cname, compress);
    case DNS_TYPE_PTR:
        return dns_rdata_ptr_to_wire (p, &rd->ptr, compress);
    case DNS_TYPE_DNAME:
        return dns_rdata_dname_to_wire (p, &rd->dname, compress);
    case DNS_TYPE_MX:
        return dns_rdata_mx_to_wire (p, &rd->mx, compress);
    case DNS_TYPE_SRV:
        return dns_rdata_srv_to_wire (p, &rd->srv, compress);
    case DNS_TYPE_SOA:
        return dns_rdata_soa_to_wire (p, &rd->soa, compress);
    case DNS_TYPE_MD:
        return dns_rdata_md_to_wire (p, &rd->md, compress);
    case DNS_TYPE_MF:
        return dns_rdata_mf_to_wire (p, &rd->mf, compress);
    case DNS_TYPE_MB:
        return dns_rdata_mb_to_wire (p, &rd->mb, compress);
    case DNS_TYPE_MG:
        return dns_rdata_mg_to_wire (p, &rd->mg, compress);
    case DNS_TYPE_MR:
        return dns_rdata_mr_to_wire (p, &rd->mr, compress);
    case DNS_TYPE_MINFO:
        return dns_rdata_minfo_to_wire (p, &rd->minfo, compress);
    case DNS_TYPE_TXT:
        return dns_rdata_txt_to_wire (p, &rd->txt, compress);
    default:
        return dns_rdata_unknown_to_wire (p, &rd->unknown, compress);
    }
}

GString *
dns_rdata_debug (const dns_rdata_t *self, dns_type_t type, dns_class_t class, GString *gs)
{
    if (!dns_rdata_known (type, class))
    {
        rdata_unknown_debug (&self->unknown, gs);
        return gs;
    }

    switch (type)
    {
    case DNS_TYPE_A:
        rdata_a_debug (&self->a, gs);
        break;
    case DNS_TYPE_AAAA:
        rdata_aaaa_debug (&self->aaaa, gs);
        break;
    case DNS_TYPE_NS:
        rdata_ns_debug (&self->ns, gs);
        break;
    case DNS_TYPE_CNAME:
        rdata_cname_debug (&self->cname, gs);
        break;
    case DNS_TYPE_PTR:
        rdata_ptr_debug (&self->ptr, gs);
        break;
    case DNS_TYPE_DNAME:
        rdata_dname_debug (&self->dname, gs);
        break;
    case DNS_TYPE_MX:
        rdata_mx_debug (&self->mx, gs);
        break;
    case DNS_TYPE_SRV:
        rdata_srv_debug (&self->srv, gs);
        break;
    case DNS_TYPE_SOA:
        rdata_soa_debug (&self->soa, gs);
        break;
    case DNS_TYPE_MD:
        rdata_md_debug (&self->md, gs);
        break;
    case DNS_TYPE_MF:
        rdata_mf_debug (&self->mf, gs);
        break;
    case DNS_TYPE_MB:
        rdata_mb_debug (&self->mb, gs);
        break;
    case DNS_TYPE_MG:
        rdata_mg_debug (&self->mg, gs);
        break;
    case DNS_TYPE_MR:
        rdata_mr_debug (&self->mr, gs);
        break;
    case DNS_TYPE_MINFO:
        rdata_minfo_debug (&self->minfo, gs);
        break;
    case DNS_TYPE_TXT:
        rdata_txt_debug (&self->txt, gs);
        break;
    default:
        rdata_unknown_debug (&self->unknown, gs);
        break;
    }
    return gs;
}
