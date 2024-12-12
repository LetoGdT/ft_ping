#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <byteswap.h>
#include <errno.h>
#include "ft_ping.h"

int update_and_print_single_stat(struct s_icmp_stat *stat, struct s_icmp_pkt * const pkt, struct s_ft_ping * ft) {
    struct timeval current_time;
    double time_diff;
    int decimal_digits;

    if (gettimeofday(&current_time, NULL)) {
        fprintf(stderr, TIME_ERROR);
        return 0;
    }
    time_diff = (current_time.tv_sec - pkt->timestamp.tv_sec) * 1000 + ((double)current_time.tv_usec - pkt->timestamp.tv_usec)/1000;
    stat->sum += time_diff;
    stat->sum_of_squared += pow(time_diff, 2);
    stat->number_of_elements++;
    if (stat->max < time_diff)
        stat->max = time_diff;
    if (stat->min > time_diff)
        stat->min = time_diff;
    printf("%ld bytes from ", sizeof(struct s_icmp_pkt));
    if (strcmp(ft->hostaddress, ft->canon_name))
        printf("%s (%s)", ft->hostname, ft->hostaddress);
    else
        printf("%s", ft->hostaddress);
    printf(": icmp_seq=%hhd ", pkt->sequence);
    if (ft->is_verbose)
        printf("ident=%d ", pkt->id);
    printf("ttl=%d ", ft->TTL);
    if (time_diff >= 1000)
        decimal_digits = 3;
    else if (time_diff < 1000 && time_diff >= 1) {
        decimal_digits = 1;
        while (time_diff / pow(10, decimal_digits) > 1) 
            decimal_digits++;
    }
    else {
        decimal_digits = 0;
        while (time_diff * pow(10, -decimal_digits) < 0.1)
            decimal_digits--;
    }
    printf("time=%.*f ms\n", 3 - decimal_digits, time_diff);
    if (ft->bell)
        printf("\a");
    return 1;
}

void print_stat(struct s_icmp_stat * stat, struct s_ft_ping const * ft) {
    struct timeval current_time;
    double time_diff;

    if (gettimeofday(&current_time, NULL)) {
        fprintf(stderr, TIME_ERROR);
        return ;
    }
    time_diff = (ft->end_time.tv_sec - ft->start_time.tv_sec) * 1000 + ((double)ft->end_time.tv_usec - ft->start_time.tv_usec) / 1000;
    if (time_diff < 0)
        time_diff = 0;
    stat->average = stat->sum / stat->number_of_elements;
    stat->mdev = sqrt(stat->sum_of_squared / stat->number_of_elements - pow(stat->average, 2));
    printf("\n--- %s ping statistics ---\n", ft->canon_name);
    printf("%d pactkets transmitted, %d received, ", ft->icmp_seq, stat->number_of_elements);
    if (ft->error_count != 0)
        printf("+%u errors, ", ft->error_count);
    printf("%.0lf%% packet loss, time %.0fms\n", 100 - ((double)stat->number_of_elements/ft->icmp_seq) * 100, time_diff);
    if (stat->number_of_elements != 0)
        printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f\n", stat->min, stat->average, stat->max, stat->mdev);
    else
        printf("\n");
}

void print_initial_message(struct s_ft_ping * ft) {
    if (ft->is_verbose){
        printf("%s: sock4.fd: %d (socktype: SOCK_RAW), hints.ai_family: AF_INET\n\n", ft->prog_name, ft->sockfd);
        printf("ai->ai->family: AF_INET, ai->ai_canonname: '%s'\n", ft->canon_name);
    }
    printf("FT_PING %s (%s) %ld bytes of data. \n", ft->canon_name, ft->hostaddress, sizeof(struct s_icmp_pkt));
}

int validate_packet(char * const raw_pkt, struct s_icmp_pkt * pkt, struct s_ft_ping * ft) {
    uint16_t old_checksum;
    enum error_code error_code;

    error_code = no_error;
    // Populate icmp_pkt struct
    memcpy(pkt, raw_pkt + (raw_pkt[0]&0xf) * 4, sizeof(struct s_icmp_pkt));
    // Put IP TTL value into ft struct
    ft->TTL = raw_pkt[8];
    // Verify icmp checksum
    old_checksum = pkt->checksum;
    // Compute checksum over the whole data, with the length retrieved from the ip header
    compute_icmp_checksum((unsigned char *)raw_pkt + (raw_pkt[0]&0xf) * 4, bswap_16(((uint16_t*)(raw_pkt))[1]) - (raw_pkt[0]&0xf) * 4);
    // Verify IP header checksum
    if (!verify_ip_checksum(raw_pkt))
        error_code = ip_chksum;
    else if (old_checksum != pkt->checksum) 
        error_code = icmp_chksum;
    else if (pkt->type != 0 || pkt->code != 0) 
        error_code = not_echo;
    else if (pkt->id != getpid())
        return 1;
    if (error_code) {
        print_error_code(raw_pkt, error_code, pkt, ft);
        return 0;
    }
    ft->hostname = reverse_dns_lookup(raw_pkt);
    return 1;
}

void print_error_code(char * const raw_pkt, enum error_code error_code, struct s_icmp_pkt * const pkt, struct s_ft_ping * const ft) {
    char * responding_server_hostname;
    char responding_server_hostaddress[INET_ADDRSTRLEN];

    responding_server_hostname = reverse_dns_lookup(raw_pkt);
    if (responding_server_hostname == NULL) {
        responding_server_hostname = strdup("");
    }
    if (inet_ntop(AF_INET, raw_pkt + 12, responding_server_hostaddress, INET_ADDRSTRLEN) == NULL) {
        responding_server_hostaddress[0] = '\0';
    }
    if (!strcmp(ft->hostaddress, ft->canon_name))
        printf("From %s: icmp_seq=%hu ", responding_server_hostaddress, ft->icmp_seq);
    else
        printf("From %s (%s): icmp_seq=%hu ", responding_server_hostname, responding_server_hostaddress, ft->icmp_seq);
    switch(error_code) {
        case ip_chksum:
            printf(IP_CHKSUM_ERR);
            break;
        case icmp_chksum:
            printf(ICMP_CHKSUM_ERR);
            break;
        default:
            if (pkt->type == 3)
                printf(DEST_UNREACHABLE);
            else if (pkt->type == 11)
                printf(TTL_EXP);
            else if (pkt->type == 12)
                printf(HDR_ERR);
            else
                printf(DFLT_ERR);
            break;
    }
    free(responding_server_hostname);
}