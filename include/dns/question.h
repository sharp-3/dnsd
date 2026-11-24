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

// Reads the question at p->cur and advances it; other errors leave p->cur unchanged.
// DNS_OK_NAME_TOO_LONG (name over DNS_NAME_MAX octets) still fills *out and advances p->cur;
// other errors leave *out unchanged.
dns_error_t
dns_question_from_bytes (dns_cursor_t *p, dns_question_t *out);
// Writes the question at p->cur and advances it; other errors leave p->cur unchanged.
// DNS_OK_NAME_TOO_LONG (name over DNS_NAME_MAX octets) still writes and advances p->cur.
dns_error_t
dns_question_to_bytes (dns_cursor_t *p, const dns_question_t *q);

const char *
dns_question_display_r (const dns_question_t *q, char *buf, size_t len);

#define dns_question_display(q)                                                                    \
    dns_question_display_r ((q), (char[DNS_QUESTION_DISPLAY_SIZE]){}, DNS_QUESTION_DISPLAY_SIZE)

#endif
