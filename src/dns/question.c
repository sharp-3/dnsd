#include <stdio.h>

#include "dns/question.h"
#include "packet/cursor.h"

static dns_error_t
question_from_bytes (dns_cursor_t *p, dns_question_t *out)
{
    cursor_t start = p->cur;

    // QNAME
    dns_name_t name;
    if (!dns_name_from_bytes (p, &name)) return p->err;

    dns_type_t  qtype  = take_bits (&p->cur, DNS_TYPE_SIZE * 8);
    dns_class_t qclass = take_bits (&p->cur, DNS_CLASS_SIZE * 8);
    if (cursor_is_overflow (&p->cur))
    {
        p->cur = start;
        return DNS_ERR_TRUNCATED;
    }

    *out = (dns_question_t){.qname = name, .qtype = qtype, .qclass = qclass};
    return DNS_OK;
}

bool
dns_question_from_bytes (dns_cursor_t *p, dns_question_t *out)
{
    if (p->err != DNS_OK) return false;
    dns_error_t warn = p->warn;
    return dns_cursor_finish (p, warn, question_from_bytes (p, out));
}

static dns_error_t
question_to_bytes (dns_cursor_t *p, const dns_question_t *q)
{
    cursor_t start = p->cur;
    if (!dns_name_to_bytes (p, &q->qname)) return p->err;

    emit_bits (&p->cur, DNS_TYPE_SIZE * 8, q->qtype);
    emit_bits (&p->cur, DNS_CLASS_SIZE * 8, q->qclass);
    if (cursor_is_overflow (&p->cur))
    {
        p->cur = start;
        return DNS_ERR_NO_SPACE;
    }
    return DNS_OK;
}

bool
dns_question_to_bytes (dns_cursor_t *p, const dns_question_t *q)
{
    if (p->err != DNS_OK) return false;
    dns_error_t warn = p->warn;
    return dns_cursor_finish (p, warn, question_to_bytes (p, q));
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
