#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include "ft_ping.h"

int dns_lookup(struct s_ft_ping *ft){
    struct addrinfo hints, *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags |= AI_CANONNAME;
    if(getaddrinfo (ft->canon_name, NULL, &hints, &result)) 
        return 0;
    ft->serv_addr = *result->ai_addr;
    freeaddrinfo(result);
    if (!inet_ntop(AF_INET, &(((struct sockaddr_in*)&ft->serv_addr)->sin_addr), ft->hostaddress, INET_ADDRSTRLEN))
    {
        fprintf(stderr, "%s\n", strerror(errno));
        return 0;
    }
    return 1;
}

char* reverse_dns_lookup(char * const raw_pkt) {
    struct sockaddr_in addr;
    char hostname[1024];

    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    memcpy(&addr.sin_addr, raw_pkt + 12, 4);
    if (getnameinfo((struct sockaddr*)&addr, sizeof(addr), hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD))
        return NULL;
    return strdup(hostname);
}
