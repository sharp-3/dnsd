#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "dns_test.h"

#define TIMEOUT_SEC 2

static void
hexdump (const char *title, const uint8_t *buf, size_t len, size_t mark)
{
    printf ("%s (%zu octets):\n", title, len);
    for (size_t i = 0; i < len; i++)
    {
        if (i % 16 == 0) printf ("  %04zx:", i);
        printf (i == mark ? " [%02x]" : " %02x", buf[i]);
        if (i % 16 == 15 || i + 1 == len) putchar ('\n');
    }
}

int
dns_test_run (int            argc,
              char         **argv,
              const uint8_t *query,
              size_t         query_len,
              const uint8_t *response,
              size_t         response_len)
{
    const char *host = 1 < argc ? argv[1] : "127.0.0.1";
    const char *port = 2 < argc ? argv[2] : "53";
    if (3 < argc)
    {
        fprintf (stderr, "usage: %s [host [port]]\n", argv[0]);
        return 2;
    }

    struct addrinfo  hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM};
    struct addrinfo *ai;
    int              rc = getaddrinfo (host, port, &hints, &ai);
    if (rc != 0)
    {
        fprintf (stderr, "%s:%s: %s\n", host, port, gai_strerror (rc));
        return 2;
    }

    int fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0 || connect (fd, ai->ai_addr, ai->ai_addrlen) < 0)
    {
        perror ("socket/connect");
        freeaddrinfo (ai);
        return 2;
    }
    freeaddrinfo (ai);

    struct timeval tv = {.tv_sec = TIMEOUT_SEC};
    setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    if (send (fd, query, query_len, 0) != (ssize_t)query_len)
    {
        perror ("send");
        close (fd);
        return 2;
    }

    static uint8_t reply[65535];
    ssize_t        n = recv (fd, reply, sizeof reply, 0);
    close (fd);

    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        if (!response)
        {
            puts ("OK (no reply)");
            return 0;
        }
        printf ("MISMATCH: no reply within %d s\n", TIMEOUT_SEC);
        hexdump ("expected", response, response_len, (size_t)-1);
        return 1;
    }
    if (n < 0)
    {
        perror ("recv");
        return 2;
    }

    size_t len = (size_t)n;
    if (!response)
    {
        puts ("MISMATCH: expected no reply");
        hexdump ("received", reply, len, (size_t)-1);
        return 1;
    }

    size_t diff = 0;
    while (diff < len && diff < response_len && reply[diff] == response[diff])
        diff++;

    if (len == response_len && diff == len)
    {
        puts ("OK");
        return 0;
    }

    printf ("MISMATCH at offset %zu\n", diff);
    hexdump ("expected", response, response_len, diff);
    hexdump ("received", reply, len, diff);
    return 1;
}
