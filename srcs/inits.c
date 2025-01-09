#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <float.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <errno.h>
#include "ft_ping.h"

void sigint_handler(int sig){
    sigint_occured = true;
}

int fill_icmp_pkt(struct s_icmp_pkt *pkt, struct s_ft_ping const * ft) {
    struct timeval t;
    
    if (gettimeofday(&t, NULL)){
        fprintf(stderr, TIME_ERROR);
        return 0;
    }
    bzero(pkt, sizeof(struct s_icmp_pkt));
    pkt->type = 8;
    pkt->code = 0;
    pkt->id = getpid();
    pkt->sequence = ft->icmp_seq;
    pkt->timestamp = t;
    if (ft->use_pattern)
        memset(pkt->data, ft->pattern, DATA_WIDTH);
    else
        memcpy(pkt->data, DFLT_DATA, strlen(DFLT_DATA));
    compute_icmp_checksum((unsigned char*)pkt, sizeof(struct s_icmp_pkt));
    return 1;
}

void initialize_stat(struct s_icmp_stat * stat) {
    stat->number_of_elements = 0;
    stat->sum = 0;
    stat->sum_of_squared = 0;
    stat->min = DBL_MAX;
    stat->max = 0;
}

int initialize_ping(struct s_ft_ping * ft, char * prog_name) {
    sigint_occured = false;
    bzero(ft, sizeof(ft));
    ft->prog_name = prog_name;
    ft->icmp_seq = 0;
    ft->error_count = 0;
    // Get current time
    if (gettimeofday(&ft->start_time, NULL)){
        fprintf(stderr, TIME_ERROR);
        return 0;
    }
    // Register signal handlers
    signal(SIGINT, sigint_handler);
    // Perform DNS lookup
    if (!dns_lookup(ft)) {
        fprintf(stderr, DNS_LKUP_ERR);
        return 0;
    }
    return 1;
}

int open_socket(struct s_ft_ping * ft) {
    int optval = 1;

    // open socket with datagram protocol
    ft->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ft->sockfd == -1) {
        fprintf(stderr, SOCK_OPEN_ERR);
        return 0;
    }
    if (ft->TTL_to_send != -1) {
        setsockopt(ft->sockfd, IPPROTO_IP, IP_TTL, &ft->TTL_to_send, sizeof(ft->TTL_to_send));
    }
    setsockopt(ft->sockfd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
    return 1;
}