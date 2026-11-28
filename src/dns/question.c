#include "dns/question.h"
#include "packet/cursor.h"

dns_error_t
dns_question_from_wire (dns_cursor_t *p, dns_question_t *out)
{
    cursor_t start = p->cur;

    dns_name_ref_t name;
    dns_error_t    err = dns_name_from_wire (p, &name);
    if (!dns_is_ok (err)) return err;

    dns_type_t  qtype  = take_bits (&p->cur, DNS_TYPE_SIZE * 8);
    dns_class_t qclass = take_bits (&p->cur, DNS_CLASS_SIZE * 8);
    if (cursor_is_overflow (&p->cur))
        return dns_cursor_rewind_return_error (start, p, DNS_ERR_TRUNCATED);

    *out = (dns_question_t){.qname = name, .qtype = qtype, .qclass = qclass};
    return err;
}

dns_error_t
dns_question_to_wire (dns_cursor_t *p, const dns_question_t *q, bool compress)
{
    cursor_t    start = p->cur;
    dns_error_t err   = dns_name_to_wire (p, &q->qname, compress);
    if (!dns_is_ok (err)) return err;

    emit_bits (&p->cur, DNS_TYPE_SIZE * 8, q->qtype);
    emit_bits (&p->cur, DNS_CLASS_SIZE * 8, q->qclass);
    if (cursor_is_overflow (&p->cur))
        return dns_cursor_rewind_return_error (start, p, DNS_ERR_NO_SPACE);
    return err;
}

GString *
dns_question_debug (const dns_question_t *self, GString *gs)
{
    dns_name_debug (&self->qname, gs);
    g_string_append_c (gs, '\t');
    dns_class_to_string (self->qclass, gs);
    g_string_append_c (gs, '\t');
    dns_type_to_string (self->qtype, gs);
    return gs;
}
