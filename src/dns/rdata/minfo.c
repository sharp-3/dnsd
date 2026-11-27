#include <string.h>

#include "common.h"
#include "packet/cursor.h"

dns_error_t
dns_rdata_minfo_from_bytes (dns_cursor_t *p, size_t len, dns_rdata_minfo_t *out)
{
    cursor_t start = p->cur;

    (void)len; // checked against RDLENGTH by the record
    dns_rdata_minfo_t rd;
    dns_error_t       err = dns_name_from_bytes (p, &rd.rmailbx);
    if (dns_is_ok (err)) err = dns_merge_soft (err, dns_name_from_bytes (p, &rd.emailbx));
    err = rdata_end (p, &start, err, DNS_ERR_TRUNCATED);
    if (dns_is_ok (err)) *out = rd;
    return err;
}

// With compress, EMAILBX may be compressed against RMAILBX too.
dns_error_t
dns_rdata_minfo_to_bytes (dns_cursor_t *p, const dns_rdata_minfo_t *rd, bool compress)
{
    cursor_t    start = p->cur;
    dns_error_t err   = dns_name_to_bytes (p, &rd->rmailbx, compress);
    if (dns_is_ok (err)) err = dns_merge_soft (err, dns_name_to_bytes (p, &rd->emailbx, compress));
    return rdata_end (p, &start, err, DNS_ERR_NO_SPACE);
}

size_t
dns_rdata_minfo_length (const dns_rdata_minfo_t *rd)
{
    return rd->rmailbx.len + rd->emailbx.len;
}

void
rdata_minfo_debug (const dns_rdata_minfo_t *rd, char *buf, size_t len)
{
    if (len == 0) return;

    // The names go straight into buf, so that a name of any length shows when buf has room.
    size_t n = strlen (dns_name_debug_r (&rd->rmailbx, buf, len));
    if (len - n < 2) return;
    buf[n++] = ' ';
    dns_name_debug_r (&rd->emailbx, buf + n, len - n);
}
