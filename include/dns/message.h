#ifndef DNSD_DNS_MESSAGE_H
#define DNSD_DNS_MESSAGE_H

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

#endif
