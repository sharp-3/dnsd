#include "server/query.h"

dns_error_t
server_query_header_validation (const dns_cursor_t *dcur, const dns_message_t *msg)
{
    (void)dcur;
    if (msg->header.qr) return DNS_ERR_NOT_QUERY;
    if (DNS_OPCODE_QUERY != msg->header.opcode) return DNS_ERR_NOT_IMPLEMENTED;
    if (1 != msg->header.qdcount) return DNS_ERR_BAD_QDCOUNT;
    if (0 != msg->header.ancount) return DNS_ERR_BAD_ANCOUNT;
    if (0 != msg->header.nscount) return DNS_ERR_BAD_NSCOUNT;
    if (0 != msg->header.arcount) return DNS_ERR_BAD_ARCOUNT;
    return DNS_OK;
}

dns_error_t
server_query_body_validation (const dns_cursor_t *dcur, const dns_message_t *msg)
{
    for (unsigned i = 0; i < msg->header.qdcount; i++)
    {
        size_t      len;
        dns_error_t err = dns_name_to_uncompressed_length (dcur, &msg->question[i].qname, &len);
        if (DNS_OK != err) return err;
    }
    return DNS_OK;
}
