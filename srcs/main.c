#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <resolv.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include "ft_ping.h"

volatile sig_atomic_t alarm_occured = false;
volatile sig_atomic_t sigint_occured = false;

void alarm_handler(int sig){
    alarm_occured = true;
}

void sigint_handler(int sig){
    sigint_occured = true;
}

int parse_arguments(int argc, char ** argv, struct s_ft_ping * ft){
    ft->is_verbose = false;
    ft->hostname = 0;
    if (argc != 2 && argc != 3){
        fprintf(stderr, "%s: Usage: %s archlinux.org [-v]\n", argv[0], argv[0]);
        return 0;
    }
    for (int i = 1 ; i < argc ; i++) {
        if (!strcmp("-v", argv[i]))
            ft->is_verbose = true;
        else
            ft->hostname = argv[i];
    }
    return 1;
}

int fill_icmp_pkt(struct s_icmp_pkt *pkt, int icmp_seq){
    struct timeval t;
    
    if (gettimeofday(&t, NULL)){
        fprintf(stderr, TIME_ERROR);
        return 0;
    }
    bzero(pkt, sizeof(struct s_icmp_pkt));
    pkt->type = 8;
    pkt->code = 0;
    pkt->id = getpid();
    pkt->sequence = icmp_seq;
    pkt->timestamp = t;
    compute_icmp_checksum((unsigned char*)pkt, sizeof(struct s_icmp_pkt));
    return 1;
}

void initialize_stat(struct s_icmp_stat * stat){
    stat->number_of_elements = 0;
    stat->sum = 0;
    stat->sum_of_squared = 0;
    stat->min = DBL_MAX;
    stat->max = 0;
}

int initialize_ping(struct s_ft_ping * ft, char * prog_name) {
    ft->prog_name = prog_name;
    ft->icmp_seq = 0;
    ft->error_count = 0;
    // Get current time
    if (gettimeofday(&ft->start_time, NULL)){
        fprintf(stderr, TIME_ERROR);
        return 0;
    }
    // Register signal handlers
    signal(SIGALRM, alarm_handler);
    signal(SIGINT, sigint_handler);
    // Perform DNS lookup
    if (!dns_lookup(ft)) {
        fprintf(stderr, "%s: %s: Name or service not known\n", ft->prog_name, ft->hostname);
        return 0;
    }
    return 1;
}

int open_socket(struct s_ft_ping * ft) {
    // open socket with datagram protocol
    ft->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ft->sockfd == -1) {
        fprintf(stderr, "%s: Cannot open socket: %s\n", ft->prog_name, strerror(errno));
        return 0;
    }
    // Connect socket
    if (connect(ft->sockfd, &ft->serv_addr, sizeof(ft->serv_addr)) == -1) {
        fprintf(stderr, "%s: Cannot connect to socket: %s\n", ft->prog_name, strerror(errno));
        close(ft->sockfd);
        return 0;
    }
    int ttl = 15;
    setsockopt(ft->sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    return 1;
}



int update_and_print_single_stat(struct s_icmp_stat *stat, struct s_icmp_pkt * const pkt, struct s_ft_ping * ft){
    struct timeval current_time;
    double time_diff;

    if (gettimeofday(&current_time, NULL)) {
        fprintf(stderr, TIME_ERROR);
        return 0;
    }
    ft->end_time = current_time;
    time_diff = (current_time.tv_sec - pkt->timestamp.tv_sec) * 1000 + ((double)current_time.tv_usec - pkt->timestamp.tv_usec)/1000;
    stat->sum += time_diff;
    stat->sum_of_squared += pow(time_diff, 2);
    stat->number_of_elements++;
    if (stat->max < time_diff)
        stat->max = time_diff;
    if (stat->min > time_diff)
        stat->min = time_diff;
    printf("%ld bytes from %s", sizeof(struct s_icmp_pkt), ft->hostname);
    if (strcmp(ft->hostaddress, ft->hostname))
        printf(" (%s): ",ft->hostaddress);
    else
        printf(": ");
    printf("icmp_seq=%hhd ", pkt->sequence);
    if (ft->is_verbose)
        printf("ident=%d ", pkt->id);
    printf("ttl=%d time=%.2f\n", ft->TTL, time_diff);
    return 1;
}


void print_stat(struct s_icmp_stat * stat, struct s_ft_ping const * ft){
    double time_diff;

    time_diff = (ft->end_time.tv_sec - ft->start_time.tv_sec) * 1000 + ((double)ft->end_time.tv_usec - ft->start_time.tv_usec)/1000;
    stat->average = stat->sum / stat->number_of_elements;
    stat->mdev = sqrt(stat->sum_of_squared / stat->number_of_elements - pow(stat->average, 2));
    printf("\n--- %s ping statistics ---\n", ft->hostname);
    printf("%d pactkets transmitted, %d received, ", ft->icmp_seq, stat->number_of_elements);
    if (ft->error_count != 0)
        printf("+%u errors, ", ft->error_count);
    printf("%d%% packet loss, time %.0fms\n", 100 - stat->number_of_elements/ft->icmp_seq * 100, time_diff);
    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f\n", stat->min, stat->average, stat->max, stat->mdev);
}

int dns_lookup(struct s_ft_ping *ft){
    struct addrinfo hints, *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags |= AI_CANONNAME;
    if(getaddrinfo (ft->hostname, NULL, &hints, &result)) 
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

void print_initial_message(struct s_ft_ping * ft){
    if (ft->is_verbose){
        printf("%s: sock4.fd: %d (socktype: SOCK_RAW), hints.ai_family: AF_INET\n\n", ft->prog_name, ft->sockfd);
        printf("ai->ai->family: AF_INET, ai->ai_canonname: '%s'\n", ft->hostname);
    }
    printf("FT_PING %s (%s) %ld bytes of data. \n", ft->hostname, ft->hostaddress, sizeof(struct s_icmp_pkt));
}

int validate_packet(char * const raw_pkt, struct s_icmp_pkt * pkt, struct s_ft_ping * ft) {
    uint16_t old_checksum;

    // Verify IP header checksum
    if (!verify_ip_checksum(raw_pkt)) {
        printf("Ip checksum error\n");
        return 0;
    }
    // Populate icmp_pkt struct
    memcpy(pkt, raw_pkt + (raw_pkt[0]&0xf) * 4, sizeof(struct s_icmp_pkt));
    // Put IP TTL value into ft struct
    ft->TTL = raw_pkt[8];
    // Verify icmp checksum
    old_checksum = pkt->checksum;
    compute_icmp_checksum((unsigned char *)pkt, sizeof(struct s_icmp_pkt));
    if (old_checksum != pkt->checksum) {
        printf("ICMP checksum error\n");
        return 0;
    }
    if (pkt->id != getpid()) {
        printf("id not recognised");
        return 0;
    }
    if (pkt->type != 0 || pkt->code != 0) {
        printf("Echo reply not received, error occured\n");
        return 0;
    }
    return 1;
}


int ping_single_loop(struct s_ft_ping * ft, struct s_icmp_pkt * pkt, struct s_icmp_stat * stat){
    unsigned char pkt_rcv_buff[RECVD_PKT_MAX_SIZE];

    ft->icmp_seq++;
    if (!fill_icmp_pkt(pkt, ft->icmp_seq)) {
        close(ft->sockfd);
        return 0;
    }
    // send echo request, with timestamp in data (ICMP type 8 code 0)
    if (send(ft->sockfd, pkt, sizeof(*pkt), 0) == -1) {
        fprintf(stderr, "%s: Cannot send packets over socket: %s\n", ft->prog_name, strerror(errno));
        close(ft->sockfd);
        return 0;
    }
    // Plan alarm signal in 1 second
    alarm(1);
    // make blocking read on socket
    memset(pkt_rcv_buff, 0, sizeof(pkt_rcv_buff));
    if (read(ft->sockfd, pkt_rcv_buff, sizeof(pkt_rcv_buff)) == -1){
        printf("%s: %s\n", ft->prog_name, strerror(errno));
        close(ft->sockfd);
        return 0;
    }
    if (!alarm_occured) {
        // Validate and pack icmp header and data into structure
        if (!validate_packet(pkt_rcv_buff, pkt, ft)) 
            return 1;
        if(!update_and_print_single_stat(stat, pkt, ft)) {
            close(ft->sockfd);
            return 0;
        }
    }
    // Wait until the alarm signal occurs or until the user requests the program stop
    while (!alarm_occured && !sigint_occured);
    alarm_occured = false;
} 

int main(int argc, char** argv){
    struct s_ft_ping ft;
    struct s_icmp_pkt pkt;
    struct s_icmp_stat stat;

    if (!parse_arguments(argc, argv, &ft))
        return 1;
    if (!initialize_ping(&ft, argv[0]))
        return 1;
    if (!open_socket(&ft))
        return 1;
    initialize_stat(&stat);
    print_initial_message(&ft);
    while (!sigint_occured)
        if (!ping_single_loop(&ft, &pkt, &stat))
            return 1;
    print_stat(&stat, &ft);
    close(ft.sockfd);
    return 0;
}