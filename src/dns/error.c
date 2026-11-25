#include "dns/error.h"

const char *
dns_error_str (dns_error_t err)
{
    switch (err)
    {
    case DNS_OK:
        return "success";
    case DNS_ERR_TRUNCATED:
        return "message truncated";
    case DNS_OK_NAME_TOO_LONG:
        return "name too long";
    case DNS_ERR_NAME_BAD_POINTER:
        return "bad compression pointer";
    case DNS_ERR_NAME_RESERVED_LABEL:
        return "reserved label type";
    case DNS_ERR_BAD_RDATA:
        return "RDLENGTH invalid for TYPE/CLASS";
    case DNS_ERR_NOMEM:
        return "out of memory";
    case DNS_ERR_NAME_LABEL_TOO_LONG:
        return "label too long";
    case DNS_ERR_BAD_TEXT:
        return "malformed text";
    case DNS_ERR_NAME_COMPRESSED:
        return "name contains a compression pointer";
    case DNS_ERR_NO_SPACE:
        return "buffer too small";
    case DNS_ERR_NOT_QUERY:
        return "message is not a query";
    case DNS_ERR_NOT_IMPLEMENTED:
        return "opcode not implemented";
    case DNS_ERR_BAD_QDCOUNT:
        return "bad QDCOUNT";
    case DNS_ERR_BAD_ANCOUNT:
        return "bad ANCOUNT";
    case DNS_ERR_BAD_NSCOUNT:
        return "bad NSCOUNT";
    case DNS_ERR_BAD_ARCOUNT:
        return "bad ARCOUNT";
    case DNS_ERR_NAME_TOO_LONG:
        return "name too long";
    case DNS_ERR_TRAILING_DATA:
        return "trailing data after message";
    case DNS_ERR_NAME_TRUNCATED:
        return "name truncated";
    case DNS_ERR_NAME_TRAILING_DATA:
        return "trailing data after name";
    }
    return "unknown error";
}
