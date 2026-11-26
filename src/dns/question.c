#include <stdio.h>
#include <string.h>

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
        dns_cursor_rewind (p, &start);
        return DNS_ERR_TRUNCATED;
    }

    *out = (dns_question_t){.qname = name, .qtype = qtype, .qclass = qclass};
    return err;
}

typedef dns_error_t (*name_write_t) (dns_cursor_t *p, const dns_name_ref_t *name);

static dns_error_t
question_write (dns_cursor_t *p, const dns_question_t *q, name_write_t name_write)
{
    cursor_t    start = p->cur;
    dns_error_t err   = name_write (p, &q->qname);
    if (!dns_is_ok (err)) return err;

    emit_bits (&p->cur, DNS_TYPE_SIZE * 8, q->qtype);
    emit_bits (&p->cur, DNS_CLASS_SIZE * 8, q->qclass);
    if (cursor_is_overflow (&p->cur))
    {
        dns_cursor_rewind (p, &start);
        return DNS_ERR_NO_SPACE;
    }
    return err;
}

dns_error_t
dns_question_to_bytes (dns_cursor_t *p, const dns_question_t *q)
{
    return question_write (p, q, dns_name_to_bytes);
}

dns_error_t
dns_question_to_bytes_with_compress (dns_cursor_t *p, const dns_question_t *q)
{
    return question_write (p, q, dns_name_to_bytes_with_compress);
}

dns_error_t
dns_question_to_uncompressed (const dns_cursor_t   *p,
                              const dns_question_t *q,
                              dns_name_t           *qname,
                              dns_question_t       *out)
{
    dns_error_t err = dns_name_to_uncompressed (p, &q->qname, qname);
    if (!dns_is_ok (err)) return err;

    *out       = *q;
    out->qname = dns_name_to_ref (qname);
    return err;
}

const char *
dns_question_display_r (const dns_question_t *q, char *buf, size_t len)
{
    if (len == 0) return buf;

    // The name goes straight into buf, so that a name of any length shows when buf has room.
    size_t n = strlen (dns_name_debug_r (&q->qname, buf, len));
    snprintf (
        buf + n, len - n, "\t%s\t%s", dns_class_display (q->qclass), dns_type_display (q->qtype));
    return buf;
}
