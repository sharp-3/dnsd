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
    case DNS_ERR_BAD_POINTER:
        return "bad compression pointer";
    case DNS_ERR_RESERVED_LABEL:
        return "reserved label type";
    case DNS_ERR_BAD_RDATA:
        return "RDLENGTH invalid for TYPE/CLASS";
    case DNS_ERR_NOMEM:
        return "out of memory";
    case DNS_ERR_LABEL_TOO_LONG:
        return "label too long";
    case DNS_ERR_BAD_TEXT:
        return "malformed text";
    case DNS_ERR_COMPRESSED:
        return "name contains a compression pointer";
    case DNS_ERR_NO_SPACE:
        return "buffer too small";
    }
    return "unknown error";
}
