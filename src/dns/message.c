#include <stdlib.h>

#include "dns/message.h"

dns_error_t
dns_message_header_from_bytes (dns_cursor_t *p, dns_message_t *out)
{
    dns_header_t hdr;
    dns_error_t  err = dns_header_from_bytes (p, &hdr);
    if (err != DNS_OK) return err;

    *out = (dns_message_t){.header = hdr};
    return DNS_OK;
}

dns_error_t
dns_message_header_query_validation (const dns_message_t *msg)
{
    if (msg->header.qr) return DNS_ERR_NOT_QUERY;
    if (msg->header.opcode != DNS_OPCODE_QUERY) return DNS_ERR_NOT_IMPLEMENTED;
    if (msg->header.qdcount != 1) return DNS_ERR_BAD_QDCOUNT;
    if (msg->header.ancount != 0) return DNS_ERR_BAD_ANCOUNT;
    if (msg->header.nscount != 0) return DNS_ERR_BAD_NSCOUNT;
    if (msg->header.arcount != 0) return DNS_ERR_BAD_ARCOUNT;
    return DNS_OK;
}

// Reads count questions into a new array stored in *out (NULL when count is 0). Errors
// leave *out unchanged.
static dns_error_t
read_questions (dns_cursor_t *p, unsigned count, dns_question_t **out, dns_error_t *soft)
{
    dns_question_t *qs = NULL;
    if (0 < count && !(qs = calloc (count, sizeof *qs))) return DNS_ERR_NOMEM;

    for (unsigned i = 0; i < count; i++)
    {
        dns_error_t err = dns_question_from_bytes (p, &qs[i]);
        if (!dns_is_ok (err))
        {
            free (qs);
            return err;
        }
        *soft = dns_merge_soft (*soft, err);
    }
    *out = qs;
    return DNS_OK;
}

// Like read_questions, for resource records.
static dns_error_t
read_records (dns_cursor_t *p, unsigned count, dns_record_t **out, dns_error_t *soft)
{
    dns_record_t *rrs = NULL;
    if (0 < count && !(rrs = calloc (count, sizeof *rrs))) return DNS_ERR_NOMEM;

    for (unsigned i = 0; i < count; i++)
    {
        dns_error_t err = dns_record_from_bytes (p, &rrs[i]);
        if (!dns_is_ok (err))
        {
            free (rrs);
            return err;
        }
        *soft = dns_merge_soft (*soft, err);
    }
    *out = rrs;
    return DNS_OK;
}

dns_error_t
dns_message_body_from_bytes (dns_cursor_t *p, dns_message_t *msg)
{
    const dns_header_t *h     = &msg->header;
    cursor_t            start = p->cur;
    dns_error_t         soft  = DNS_OK;
    dns_question_t     *qd    = NULL;
    dns_record_t       *an = NULL, *ns = NULL, *ar = NULL;

    dns_error_t err = read_questions (p, h->qdcount, &qd, &soft);
    if (err == DNS_OK) err = read_records (p, h->ancount, &an, &soft);
    if (err == DNS_OK) err = read_records (p, h->nscount, &ns, &soft);
    if (err == DNS_OK) err = read_records (p, h->arcount, &ar, &soft);
    if (err != DNS_OK)
    {
        free (qd);
        free (an);
        free (ns);
        free (ar);
        dns_cursor_rewind (p, &start);
        return err;
    }

    msg->question   = qd;
    msg->answer     = an;
    msg->authority  = ns;
    msg->additional = ar;
    return soft;
}

dns_error_t
dns_message_body_query_validation (const dns_cursor_t *p, const dns_message_t *msg)
{
    for (unsigned i = 0; i < msg->header.qdcount; i++)
    {
        size_t      len;
        dns_error_t err = dns_name_to_uncompressed_length (p, &msg->question[i].qname, &len);
        if (err != DNS_OK) return err;
    }
    return DNS_OK;
}

dns_error_t
dns_message_query_validation (const dns_cursor_t *p, const dns_message_t *msg)
{
    dns_error_t err = dns_message_header_query_validation (msg);
    if (err != DNS_OK) return err;

    err = dns_message_body_query_validation (p, msg);
    if (err == DNS_OK_NAME_TOO_LONG) return DNS_ERR_NAME_TOO_LONG;
    if (err != DNS_OK) return err;

    if (!cursor_is_aligned (&p->cur) || cursor_bytes (&p->cur) != p->cur.len)
        return DNS_ERR_TRAILING_DATA;
    return DNS_OK;
}

void
dns_message_free (dns_message_t *msg)
{
    if (!msg) return;
    free (msg->question);
    free (msg->answer);
    free (msg->authority);
    free (msg->additional);
    msg->question   = NULL;
    msg->answer     = NULL;
    msg->authority  = NULL;
    msg->additional = NULL;
}
