#define _POSIX_C_SOURCE 200809L

#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "dns/header.h"
#include "dns/name.h"
#include "dns/params/class.h"
#include "dns/params/type.h"
#include "dns/question.h"
#include "dns/record.h"

#define TIMEOUT_MS 3000
#define TRIES 3
#define UDP_MAX 512
#define MSG_MAX 65535
#define RECORD_NAMES_MAX 3 // most domain names in one record (owner, SOA MNAME and RNAME)

#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif

static char record_line[1 << 19];
static bool expand;
// Room for each name of one record once expanded (at most the message size; see
// dns_name_expand).
static uint8_t expanded[RECORD_NAMES_MAX * MSG_MAX];

static void
usage (void)
{
    fprintf (
        stderr,
        "usage: query [@server] [-p port] [+tcp] [+expand] [+[no]FLAG ...] name [type] [class]\n"
        "       FLAG: qr aa tc rd ra z ad cd (default: rd on, others off)\n");
    exit (1);
}

// +FLAG sets a header flag, +noFLAG clears it.
static bool
parse_flag (const char *a, dns_header_t *hdr)
{
    if (a[0] != '+') return false;

    bool        on = strncmp (a + 1, "no", 2) != 0;
    const char *f  = on ? a + 1 : a + 3;
    struct
    {
        const char *name;
        bool       *bit;
    } flags[] = {
        {"qr", &hdr->qr},
        {"aa", &hdr->aa},
        {"tc", &hdr->tc},
        {"rd", &hdr->rd},
        {"ra", &hdr->ra},
        {"z", &hdr->z},
        {"ad", &hdr->ad},
        {"cd", &hdr->cd},
    };
    for (size_t i = 0; i < sizeof flags / sizeof flags[0]; i++)
    {
        if (strcmp (f, flags[i].name) == 0)
        {
            *flags[i].bit = on;
            return true;
        }
    }
    return false;
}

static const char *
default_server (void)
{
    static char addr[256];
    FILE       *fp = fopen ("/etc/resolv.conf", "r");
    char        line[512];

    if (fp)
    {
        while (fgets (line, sizeof line, fp))
        {
            if (sscanf (line, " nameserver %255s", addr) == 1)
            {
                fclose (fp);
                return addr;
            }
        }
        fclose (fp);
    }
    return "127.0.0.1";
}

static uint16_t
random_id (void)
{
    uint16_t id = 0;
    FILE    *fp = fopen ("/dev/urandom", "rb");
    if (!fp || fread (&id, sizeof id, 1, fp) != 1)
    {
        struct timespec ts;
        clock_gettime (CLOCK_REALTIME, &ts);
        id = (uint16_t)(ts.tv_nsec ^ getpid ());
    }
    if (fp) fclose (fp);
    return id;
}

static long
elapsed_ms (const struct timespec *start)
{
    struct timespec now;
    clock_gettime (CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000 + (now.tv_nsec - start->tv_nsec) / 1000000;
}

static bool
wait_readable (int fd, int timeout_ms)
{
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    return poll (&pfd, 1, timeout_ms) == 1;
}

static int
connect_to (const struct addrinfo *ai)
{
    int fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) return -1;
    if (connect (fd, ai->ai_addr, ai->ai_addrlen) < 0)
    {
        close (fd);
        return -1;
    }
    return fd;
}

static ssize_t
exchange_udp (const struct addrinfo *ai, const uint8_t *q, size_t qlen, uint8_t *r, size_t rmax)
{
    int fd = connect_to (ai);
    if (fd < 0) return -1;

    ssize_t n = -1;
    for (int i = 0; i < TRIES && n < 0; i++)
    {
        if (send (fd, q, qlen, 0) != (ssize_t)qlen) break;
        while (wait_readable (fd, TIMEOUT_MS))
        {
            n = recv (fd, r, rmax, 0);
            if (n >= 2 && r[0] == q[0] && r[1] == q[1]) break;
            n = -1;
        }
    }

    close (fd);
    return n;
}

static bool
read_full (int fd, uint8_t *buf, size_t len)
{
    for (size_t got = 0; got < len;)
    {
        if (!wait_readable (fd, TIMEOUT_MS)) return false;
        ssize_t n = recv (fd, buf + got, len - got, 0);
        if (n <= 0) return false;
        got += n;
    }
    return true;
}

static ssize_t
exchange_tcp (const struct addrinfo *ai, const uint8_t *q, size_t qlen, uint8_t *r, size_t rmax)
{
    int fd = connect_to (ai);
    if (fd < 0) return -1;

    uint8_t prefix[2] = {qlen >> 8, qlen & 0xff};
    ssize_t n         = -1;
    if (send (fd, prefix, 2, 0) == 2 && send (fd, q, qlen, 0) == (ssize_t)qlen &&
        read_full (fd, prefix, 2))
    {
        size_t len = (size_t)prefix[0] << 8 | prefix[1];
        if (len <= rmax && read_full (fd, r, len)) n = len;
    }

    close (fd);
    return n;
}

static bool
print_records (const char *title, unsigned count, dns_cursor_t *p)
{
    if (count == 0) return true;

    printf ("\n;; %s SECTION:\n", title);
    for (unsigned i = 0; i < count; i++)
    {
        dns_record_t record;
        dns_error_t  err = dns_record_from_bytes (p, &record);
        if (err != DNS_OK)
            printf (";; error in %s section, record %u: %s\n", title, i + 1, dns_error_str (err));
        if (!dns_is_ok (err)) return false;
        if (expand) dns_record_expand (p, &record, expanded, sizeof expanded, &record);
        puts (dns_record_display_r (&record, record_line, sizeof record_line));
    }
    return true;
}

static bool
print_reply (uint8_t *msg, size_t len)
{
    static dns_cursor_t parser;
    dns_cursor_init (&parser, msg, len);

    dns_header_t header;
    dns_error_t  err = dns_header_from_bytes (&parser, &header);
    if (err != DNS_OK)
    {
        printf (";; error in header: %s\n", dns_error_str (err));
        return false;
    }

    const dns_header_t *hdr = &header;
    printf (";; ->>HEADER<<- %s\n", dns_header_display (hdr));

    bool ok = true;
    if (hdr->qdcount) printf ("\n;; QUESTION SECTION:\n");
    for (unsigned i = 0; ok && i < hdr->qdcount; i++)
    {
        dns_question_t question;
        if ((err = dns_question_from_bytes (&parser, &question)) != DNS_OK)
            printf (";; error in QUESTION section: %s\n", dns_error_str (err));
        if (!dns_is_ok (err))
        {
            ok = false;
            break;
        }
        dns_question_t *q = &question;
        if (expand)
        {
            dns_name_t full;
            err = dns_name_expand (&parser, &q->qname, expanded, sizeof expanded, &full);
            if (err != DNS_OK) printf (";; error in QUESTION section: %s\n", dns_error_str (err));
            if (dns_is_ok (err)) q->qname = full;
        }
        printf (";%s\n", dns_question_display (q));
    }

    ok = ok && print_records ("ANSWER", hdr->ancount, &parser) &&
         print_records ("AUTHORITY", hdr->nscount, &parser) &&
         print_records ("ADDITIONAL", hdr->arcount, &parser);
    size_t off = cursor_bytes (&parser.cur);
    if (ok && off != len) printf (";; warning: %zu trailing octets\n", len - off);

    return ok;
}

int
main (int argc, char **argv)
{
    const char  *server    = NULL;
    const char  *port      = "53";
    const char  *qname     = NULL;
    bool         tcp       = false;
    bool         have_type = false, have_class = false;
    dns_type_t   qtype  = DNS_TYPE_A;
    dns_class_t  qclass = DNS_CLASS_IN;
    dns_header_t hdr = {.id = random_id (), .opcode = DNS_OPCODE_QUERY, .rd = true, .qdcount = 1};

    for (int i = 1; i < argc; i++)
    {
        const char *a = argv[i];
        if (a[0] == '@' && a[1]) server = a + 1;
        else if (strcmp (a, "-p") == 0 && i + 1 < argc) port = argv[++i];
        else if (strcmp (a, "+tcp") == 0) tcp = true;
        else if (strcmp (a, "+expand") == 0) expand = true;
        else if (parse_flag (a, &hdr)) continue;
        else if (a[0] == '+') usage ();
        else if (!qname) qname = a;
        else if (!have_type && dns_type_from_string (a, &qtype) == DNS_OK) have_type = true;
        else if (!have_class && dns_class_from_string (a, &qclass) == DNS_OK) have_class = true;
        else usage ();
    }
    if (!qname) usage ();
    if (!server) server = default_server ();

    // A name too long for this buffer would not fit in the query either.
    uint8_t     name_buf[UDP_MAX];
    dns_name_t  name;
    dns_error_t err = dns_name_from_string (qname, name_buf, sizeof name_buf, &name);
    if (err != DNS_OK) fprintf (stderr, "query: bad name '%s': %s\n", qname, dns_error_str (err));
    if (!dns_is_ok (err)) return 1;

    dns_question_t      q = {.qname = name, .qtype = qtype, .qclass = qclass};
    uint8_t             query[UDP_MAX];
    static dns_cursor_t writer;
    dns_cursor_init (&writer, query, sizeof query);
    err = dns_header_to_bytes (&writer, &hdr);
    if (err == DNS_OK) err = dns_question_to_bytes (&writer, &q);
    size_t qlen = cursor_bytes (&writer.cur);
    if (!dns_is_ok (err))
    {
        fprintf (stderr, "query: cannot build query: %s\n", dns_error_str (err));
        return 1;
    }

    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = tcp ? SOCK_STREAM : SOCK_DGRAM};
    struct addrinfo *ai;
    int              gai = getaddrinfo (server, port, &hints, &ai);
    if (gai != 0)
    {
        fprintf (stderr, "query: %s: %s\n", server, gai_strerror (gai));
        return 1;
    }

    char host[NI_MAXHOST] = "?";
    getnameinfo (ai->ai_addr, ai->ai_addrlen, host, sizeof host, NULL, 0, NI_NUMERICHOST);

    printf ("; <<>> query <<>> %s %s %s\n",
            qname,
            dns_type_display (qtype),
            dns_class_display (qclass));

    static uint8_t  reply[MSG_MAX];
    struct timespec start;
    clock_gettime (CLOCK_MONOTONIC, &start);

    ssize_t rlen;
    if (tcp)
    {
        rlen = exchange_tcp (ai, query, qlen, reply, sizeof reply);
    }
    else
    {
        rlen = exchange_udp (ai, query, qlen, reply, sizeof reply);
        if (rlen >= DNS_HEADER_SIZE && (reply[2] & 0x02))
        {
            printf (";; Truncated, retrying in TCP mode.\n");
            struct addrinfo  thints = {.ai_family = ai->ai_family, .ai_socktype = SOCK_STREAM};
            struct addrinfo *tai;
            tcp = true;
            if (getaddrinfo (host, port, &thints, &tai) == 0)
            {
                rlen = exchange_tcp (tai, query, qlen, reply, sizeof reply);
                freeaddrinfo (tai);
            }
            else
            {
                rlen = -1;
            }
        }
    }
    long ms = elapsed_ms (&start);
    freeaddrinfo (ai);

    if (rlen < 0)
    {
        printf (";; connection timed out; no servers could be reached\n");
        return 9;
    }

    bool ok = print_reply (reply, (size_t)rlen);

    printf ("\n;; Query time: %ld msec\n", ms);
    printf (";; SERVER: %s#%s(%s)\n", host, port, tcp ? "TCP" : "UDP");
    printf (";; MSG SIZE  rcvd: %zd\n", rlen);

    return ok ? 0 : 10;
}
