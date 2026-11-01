#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <packet/dns/hdr.h>

#define ADDR "127.0.0.2"
#define PORT 53

int
main(void)
{
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket creation failed");
        exit(1);
    }

    struct sockaddr_in servaddr = {0};
    servaddr.sin_family         = AF_INET;
    servaddr.sin_addr.s_addr    = inet_addr(ADDR);
    servaddr.sin_port           = htons(PORT);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        perror("bind failed");
        close(sockfd);
        exit(1);
    }

    while (1)
    {
        struct sockaddr_in cliaddr     = {0};
        socklen_t          clilen      = sizeof(cliaddr);
        uint8_t            buffer[513] = {0};
        size_t nread = recvfrom(sockfd, buffer, 513, 0, (struct sockaddr *)&cliaddr, &clilen);

        if (nread < 0)
        {
            perror("recvfrom failed");
            break;
        }

        dns_hdr_t hdr;
        int       result = 0;
        hdr              = dns_hdr_deserialise(buffer, nread, &result);
        if (result != 0) continue;
        dns_hdr_print(&hdr);
    }

    close(sockfd);
    return 0;
}
