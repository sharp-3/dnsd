#ifndef DNSD_DNS_QUESTION_H
#define DNSD_DNS_QUESTION_H

#include <stddef.h>
#include <stdint.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"
#include "dns/params/class.h"
#include "dns/params/type.h"

#define DNS_QUESTION_DISPLAY_SIZE                                                                  \
    (sizeof "\t\t" + (DNS_NAME_DEBUG_SIZE - 1) + (DNS_TYPE_DISPLAY_SIZE - 1) +                     \
     (DNS_CLASS_DISPLAY_SIZE - 1))

typedef struct
{
    dns_name_t  qname;  // name being queried
    dns_type_t  qtype;  // type being queried
    dns_class_t qclass; // class being queried
} dns_question_t;

// dns_question_t <--> uint8_t * (wire format)
dns_error_t
dns_question_from_bytes (dns_cursor_t *p, dns_question_t *out);
dns_error_t
dns_question_to_bytes (dns_cursor_t *p, const dns_question_t *q);

// compressed <--> expanded
dns_error_t
dns_question_expand (
    const dns_cursor_t *p, const dns_question_t *q, uint8_t *buf, size_t len, dns_question_t *out);
dns_error_t
dns_question_compress (
    const dns_cursor_t *p, const dns_question_t *q, uint8_t *buf, size_t len, dns_question_t *out);

// display
const char *
dns_question_display_r (const dns_question_t *q, char *buf, size_t len);

#define dns_question_display(q)                                                                    \
    dns_question_display_r ((q), (char[DNS_QUESTION_DISPLAY_SIZE]){}, DNS_QUESTION_DISPLAY_SIZE)

#endif
