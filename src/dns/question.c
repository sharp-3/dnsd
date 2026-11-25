#include <stdio.h>

#include "dns/question.h"
#include "packet/cursor.h"

dns_error_t
dns_question_from_bytes (dns_cursor_t *p, dns_question_t *out)
{
    cursor_t start = p->cur;

    // QNAME
    dns_name_ref_t name;
    dns_error_t    err = dns_name_from_bytes (p, &name);
    if (!dns_is_ok (err)) return err;

    dns_type_t  qtype  = take_bits (&p->cur, DNS_TYPE_SIZE * 8);
    dns_class_t qclass = take_bits (&p->cur, DNS_CLASS_SIZE * 8);
    if (cursor_is_overflow (&p->cur))
    {
        p->cur = start;
        return DNS_ERR_TRUNCATED;
    }

    *out = (dns_question_t){.qname = name, .qtype = qtype, .qclass = qclass};
    return err;
}

dns_error_t
dns_question_to_bytes (dns_cursor_t *p, const dns_question_t *q)
{
    cursor_t    start = p->cur;
    dns_error_t err   = dns_name_to_bytes (p, &q->qname);
    if (!dns_is_ok (err)) return err;

    emit_bits (&p->cur, DNS_TYPE_SIZE * 8, q->qtype);
    emit_bits (&p->cur, DNS_CLASS_SIZE * 8, q->qclass);
    if (cursor_is_overflow (&p->cur))
    {
        p->cur = start;
        dns_cursor_clear_labels (p, cursor_bytes (&start));
        return DNS_ERR_NO_SPACE;
    }
    return err;
}

dns_error_t
dns_question_expand (const dns_cursor_t   *p,
                     const dns_question_t *q,
                     dns_name_t           *qname,
                     dns_question_t       *out)
{
    dns_error_t err = dns_name_expand (p, &q->qname, qname);
    if (!dns_is_ok (err)) return err;

    *out       = *q;
    out->qname = dns_name_to_ref (qname);
    return err;
}

dns_error_t
dns_question_compress (const dns_cursor_t   *p,
                       const dns_question_t *q,
                       dns_name_t           *qname,
                       dns_question_t       *out)
{
    dns_error_t err = dns_name_compress (p, &q->qname, qname);
    if (!dns_is_ok (err)) return err;

    *out       = *q;
    out->qname = dns_name_to_ref (qname);
    return err;
}

const char *
dns_question_display_r (const dns_question_t *q, char *buf, size_t len)
{
    snprintf (buf,
              len,
              "%s\t%s\t%s",
              dns_name_debug (&q->qname),
              dns_class_display (q->qclass),
              dns_type_display (q->qtype));
    return buf;
}
