#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <byteswap.h>
#include <netdb.h>
#include "ft_ping.h"

volatile sig_atomic_t sigint_occured;

int parse_arguments(int argc, char ** argv, struct s_ft_ping * ft){
    int opt;
    
    ft->is_verbose = false;
    ft->canon_name = 0;
    ft->TTL_to_send = -1;
    ft->cycle_time = CYCLE_TIME;
    ft->number_of_requests_to_send = -1;
    ft->bell = false;
    while ((opt = getopt(argc, argv, ":ac:i:p:t:vh")) != -1) {
        switch (opt){
            case 'a':
                ft->bell = true;
                break;
            case 'c':
                ft->number_of_requests_to_send = atoi(optarg);
                break;
            case 'i':
                ft->cycle_time = atof(optarg) * pow(10, 3);
                break;
            case 'p':
                ft->use_pattern = true;
                optarg[2] = '\0';
                ft->pattern = (unsigned char)strtol(optarg, NULL, 16);
                break;
            case 't':
                ft->TTL_to_send = atoi(optarg);
                break;
            case 'v':
                ft->is_verbose = true;
                break;
            case ':':
                fprintf(stderr, ARG_NEEDED);
            case '?':
            case 'h':
            default:
                printf(USAGE);
                return 0;
        }
    }
    if (optind < argc)
        while (optind < argc)
            ft->canon_name = argv[optind++];
    if (ft->canon_name == 0) {
        printf(MISSING_DEST);
        return 0;
    }
    return 1;
}

int read_loop(struct s_ft_ping * ft, struct s_icmp_pkt * pkt, struct s_icmp_stat * stat, struct timeval * loop_start) {
    struct timespec timeout;
    unsigned char pkt_rcv_buff[RECVD_PKT_MAX_SIZE];
    int ready_count;
    fd_set read_fds;
    struct timeval current_time;
    double timediff;

    ready_count = 0;
    if (gettimeofday(&current_time, NULL)) {
        fprintf(stderr, TIME_ERROR);
        close(ft->sockfd);
        return 0;
    }
    do {
        FD_ZERO(&read_fds);
        FD_SET(ft->sockfd, &read_fds);
        timediff = (current_time.tv_sec - loop_start->tv_sec) * pow(10, 6) + current_time.tv_usec - loop_start->tv_usec;
        timeout.tv_nsec = ft->cycle_time * pow(10, 6) - timediff * pow(10, 3);
        timeout.tv_sec = timeout.tv_nsec / (int)pow(10, 9);
        timeout.tv_nsec %= (int)pow(10, 9);
        // Wait for data to arrive on the socket
        ready_count = pselect(ft->sockfd + 1, &read_fds, NULL, NULL, &timeout, NULL);
        if (ready_count < 0) {
            // Case where user requested the program stop by CTRL-C
            if (errno == EINTR) {
                ft->icmp_seq--;
                return 1;
            }
            // Case where pselect had an error
            fprintf(stderr, PRINT_STRERROR);
            return 0;
        }
        // Case where the timeout expired and no data was received
        else if (ready_count == 0 || !FD_ISSET(ft->sockfd, &read_fds))
            return 1;
        // Case where data was received
        memset(pkt_rcv_buff, 0, sizeof(pkt_rcv_buff));
        if (read(ft->sockfd, pkt_rcv_buff, sizeof(pkt_rcv_buff)) == -1){
            fprintf(stderr, PRINT_STRERROR);
            return 0;
        }
        // Validate and pack icmp header and data into structure
        if (!validate_packet(pkt_rcv_buff, pkt, ft)) {
            if (!ft->hostname)
                return 0;
            return 1;
        }
        if(!update_and_print_single_stat(stat, pkt, ft)) {
            free(ft->hostname);
            return 0;
        }
        free(ft->hostname);
        // The data has been received and treated properly
        return 1;
    } while (timediff > 0);
    return 1;
}

int ping_single_loop(struct s_ft_ping * ft, struct s_icmp_pkt * pkt, struct s_icmp_stat * stat){
    struct timeval loop_start;
    struct timeval loop_end;
    long int timediff;

    ft->icmp_seq++;
    if (!fill_icmp_pkt(pkt, ft)) {
        close(ft->sockfd);
        return 0;
    }
    if (gettimeofday(&loop_start, NULL)) {
        fprintf(stderr, TIME_ERROR);
        close(ft->sockfd);
        return 0;
    }
    ft->end_time = loop_start;
    // send echo request, with timestamp in data (ICMP type 8 code 0)
    if (sendto(ft->sockfd, pkt, sizeof(*pkt), 0, &ft->serv_addr, sizeof(struct sockaddr)) == -1) {
        fprintf(stderr, SEND_ERROR, ft->prog_name, strerror(errno));
        close(ft->sockfd);
        return 0;
    }
    if (!read_loop(ft, pkt, stat, &loop_start)) {
        close(ft->sockfd);
        return 0;
    }
    if (gettimeofday(&loop_end, NULL)) {
        fprintf(stderr, TIME_ERROR);
        close(ft->sockfd);
        return 0;
    }
    // Compute remaining time to sleep so that the loop is 1 second
    timediff = ft->cycle_time * pow(10, 3) - ((loop_end.tv_sec - loop_start.tv_sec) * pow(10, 6) + (loop_end.tv_usec - loop_start.tv_usec));
    if (timediff > 0) {
        sleep(timediff / (int)pow(10, 6));
        usleep(timediff % (int)pow(10, 6));
    }
    return 1;
} 

int main(int argc, char** argv){
    struct s_ft_ping ft;
    struct s_icmp_stat stat;
    struct s_icmp_pkt pkt;

    if (!parse_arguments(argc, argv, &ft))
        return 1;
    if (!initialize_ping(&ft, argv[0]))
        return 1;
    if (!open_socket(&ft))
        return 1;
    initialize_stat(&stat);
    print_initial_message(&ft);
    while (!sigint_occured && ft.icmp_seq != ft.number_of_requests_to_send)
        if (!ping_single_loop(&ft, &pkt, &stat))
            return 1;
    print_stat(&stat, &ft);
    close(ft.sockfd);
    return 0;
}