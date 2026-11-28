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

// dns_message_t <-- uint8_t * (wire format)
dns_error_t
dns_message_header_from_wire (dns_cursor_t *p, dns_message_t *out);
dns_error_t
dns_message_body_from_wire (dns_cursor_t *p, dns_message_t *msg);

// query validation
dns_error_t
dns_message_header_query_validation (const dns_message_t *msg);
dns_error_t
dns_message_body_query_validation (const dns_cursor_t *p, const dns_message_t *msg);
dns_error_t
dns_message_query_validation (const dns_cursor_t *p, const dns_message_t *msg);

// memory
void
dns_message_free (dns_message_t *msg);

#endif
