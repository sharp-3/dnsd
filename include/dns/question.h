#ifndef DNSD_DNS_QUESTION_H
#define DNSD_DNS_QUESTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <glib.h>

#include "dns/cursor.h"
#include "dns/error.h"
#include "dns/name.h"
#include "dns/params/class.h"
#include "dns/params/type.h"

typedef struct
{
    dns_name_ref_t qname;  // name being queried
    dns_type_t     qtype;  // type being queried
    dns_class_t    qclass; // class being queried
} dns_question_t;

// dns_question_t <--> uint8_t * (wire format)
dns_error_t
dns_question_from_wire (dns_cursor_t *p, dns_question_t *out);
dns_error_t
dns_question_to_wire (dns_cursor_t *p, const dns_question_t *q, bool compress);

// debug
GString *
dns_question_debug (const dns_question_t *self, GString *gs);

#endif
