#ifndef DNSD_DNS_MESSAGE_H
#define DNSD_DNS_MESSAGE_H

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/header.h"
#include "dns/question.h"
#include "dns/record.h"

typedef struct
{
    dns_header_t    header;     // header section
    dns_question_t *question;   // header.qdcount entries
    dns_record_t   *answer;     // header.ancount entries
    dns_record_t   *authority;  // header.nscount entries
    dns_record_t   *additional; // header.arcount entries
} dns_message_t;

// Reads the header at p->cur into *out with all sections NULL, and advances p->cur; errors
// leave p->cur and *out unchanged. *out is overwritten, so free an earlier message first.
dns_error_t
dns_message_header_from_bytes (dns_cursor_t *p, dns_message_t *out);
// DNS_ERR_NOT_QUERY: QR is set (do not reply). DNS_ERR_NOT_IMPLEMENTED: OPCODE is not QUERY.
// DNS_ERR_BAD_QDCOUNT: QDCOUNT is not 1.
// DNS_ERR_BAD_ANCOUNT / _NSCOUNT / _ARCOUNT: that count is not 0.
dns_error_t
dns_message_header_query_validation (const dns_message_t *msg);
// Reads all four sections as counted in msg->header, starting at p->cur.
// DNS_OK_NAME_TOO_LONG (name over DNS_NAME_MAX octets) still fills the sections and advances
// p->cur; on any other error msg and p->cur are unchanged.
dns_error_t
dns_message_body_from_bytes (dns_cursor_t *p, dns_message_t *msg);
// Call after dns_message_body_from_bytes returned DNS_OK or DNS_OK_NAME_TOO_LONG.
// DNS_OK_NAME_TOO_LONG: a question name is longer than DNS_NAME_MAX octets once expanded
// (the caller decides whether to reject it).
dns_error_t
dns_message_body_query_validation (const dns_cursor_t *p, const dns_message_t *msg);
// Checks a whole query: call right after dns_message_body_from_bytes returned DNS_OK or
// DNS_OK_NAME_TOO_LONG, with p->cur still at the end of the body.
// Returns what dns_message_header_query_validation returns, any hard error from expanding
// the question names, and:
// DNS_ERR_NAME_TOO_LONG: a question name is longer than DNS_NAME_MAX octets once expanded.
// DNS_ERR_TRAILING_DATA: p->cur is not at the end of the packet.
dns_error_t
dns_message_query_validation (const dns_cursor_t *p, const dns_message_t *msg);
// Frees the sections and sets them to NULL; msg itself belongs to the caller.
void
dns_message_free (dns_message_t *msg);

#endif
