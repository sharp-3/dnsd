#ifndef DNSD_SERVER_QUERY_H
#define DNSD_SERVER_QUERY_H

#include "dns/cursor.h"
#include "dns/message.h"

// query validation
dns_error_t
server_query_header_validation (const dns_cursor_t *dcur, const dns_message_t *msg);
dns_error_t
server_query_body_validation (const dns_cursor_t *dcur, const dns_message_t *msg);

#endif
