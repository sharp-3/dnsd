#include <stdio.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
rdata_end (dns_cursor_t *p, const cursor_t *start, dns_error_t err, dns_error_t overflow_err)
{
    if (dns_is_ok (err) && cursor_is_overflow (&p->cur)) err = overflow_err;
    if (dns_is_ok (err)) return err;
    p->cur = *start;
    dns_cursor_clear_labels (p, cursor_bytes (start));
    return err;
}

dns_error_t
rdata_name_from_bytes (dns_cursor_t *p, size_t len, dns_name_ref_t *out)
{
    (void)len; // checked against RDLENGTH by the record
    return dns_name_from_bytes (p, out);
}

dns_error_t
rdata_name_to_bytes (dns_cursor_t *p, const dns_name_ref_t *name)
{
    cursor_t start = p->cur;
    return rdata_end (p, &start, dns_name_to_bytes (p, name), DNS_ERR_NO_SPACE);
}

void
rdata_name_display (const dns_name_ref_t *name, char *buf, size_t len)
{
    snprintf (buf, len, "%s", dns_name_debug (name));
}
