#include <unistd.h>
#include <signal.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <resolv.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <sys/time.h>
#include "ft_ping.h"
#define TTL 255 // check this value

volatile sig_atomic_t alarm_occured = false;
volatile sig_atomic_t sigint_occured = false;

void alarm_handler(int sig){
    alarm_occured = true;
}

void sigint_handler(int sig){
    sigint_occured = true;
}

int fill_icmp_pkt(struct s_icmp_pkt *pkt, int icmp_seq){
    struct timeval t;
    
    if (gettimeofday(&t, NULL)){
        printf(TIME_ERROR);
        return 0;
    }
    bzero(pkt, sizeof(struct s_icmp_pkt));
    pkt->type = 8;
    pkt->code = 0;
    pkt->id = getpid();
    pkt->sequence = icmp_seq;
    pkt->timestamp = t;
    compute_checksum((unsigned char*)pkt, sizeof(struct s_icmp_pkt));
    return 1;
}

void initialize_stat(struct s_icmp_stat * stat){
    stat->number_of_elements = 0;
    stat->sum = 0;
    stat->sum_of_squared = 0;
    stat->min = DBL_MAX;
    stat->max = 0;
}

int update_and_print_single_stat(struct s_icmp_stat *stat, struct s_icmp_pkt * const pkt, struct s_ft_ping * ft){
    struct timeval current_time;
    double time_diff;

    if(gettimeofday(&current_time, NULL)) {
        printf(TIME_ERROR);
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
   // printf("%d %d %d %d %d", pkt->type, pkt->code, pkt->checksum, pkt->id, pkt->sequence);
   // printf("%d %f %f %f %f %f %f\n", stat->number_of_elements, stat->sum, stat->sum_of_squared, stat->average, stat->mdev, stat->min, stat->max);
    printf("%ld bytes from %s: icmp_seq=%d ttl=%d time=%.2f\n", sizeof(struct s_icmp_pkt), ft->addr, pkt->sequence, 58, time_diff);
    return 1;
}


void print_stat(struct s_icmp_stat * stat, struct s_ft_ping const * ft){
    double time_diff;

    time_diff = (ft->end_time.tv_sec - ft->start_time.tv_sec) * 1000 + ((double)ft->end_time.tv_usec - ft->start_time.tv_usec)/1000;
    stat->average = stat->sum / stat->number_of_elements;
    stat->mdev = sqrt(stat->sum_of_squared / stat->number_of_elements - pow(stat->average, 2));
    printf("\n--- %s ping statistics ---\n", ft->addr);
    printf("%d pactkets transmitted, %d received, %d%% packet loss, time %.0fms\n", ft->icmp_seq, stat->number_of_elements, 100 - stat->number_of_elements/ft->icmp_seq * 100, time_diff);
    printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f\n", stat->min, stat->average, stat->max, stat->mdev);
}

int main(int argc, char** argv){
    struct s_ft_ping ft;
    struct s_icmp_pkt pkt;
    struct s_icmp_stat stat;


    


    ft.addr = "1.1.1.1";
    ft.icmp_seq = 0;
    printf("%ld\n", sizeof(struct s_icmp_pkt));
    // parse arguments
    signal(SIGALRM, alarm_handler);
    signal(SIGINT, sigint_handler);
    // make dns query or parse addr
    if (inet_pton(AF_INET, ft.addr, &ft.serv_addr.sin_addr) != 1) {
        printf("%s: %s: Name or service not known", argv[0], ft.addr);
        return 2;
    }
    // open socket with datagram protocol
    ft.sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (ft.sockfd == -1) {
        printf("%s\n", strerror(errno));
        return 1;
    }
    ft.serv_addr.sin_family = AF_INET;
    // Connect socket
    if (connect(ft.sockfd, (struct sockaddr*)&ft.serv_addr, sizeof(ft.serv_addr)) == -1) {
        printf("%s: %s\n", argv[0], strerror(errno));
        close(ft.sockfd);
        return 1;
    }
    initialize_stat(&stat);
    if (gettimeofday(&ft.start_time, NULL)){
        printf(TIME_ERROR);
        return 1;
    }
    while (!sigint_occured) {
        if (!fill_icmp_pkt(&pkt, ft.icmp_seq))
            return 1;
        // send echo request, with timestamp in data (ICMP type 8 code 0)
        if (send(ft.sockfd, &pkt, sizeof(pkt), 0) == -1) {
            printf("%s: %s\n", argv[0], strerror(errno));
            return 1;
        }
        ft.icmp_seq++;
        alarm(1);
        // make blocking read on socket waiting for echo reply (ICMP type 0 code 0)
        if (read(ft.sockfd, &pkt, sizeof(pkt)) == -1){
            printf("%s: %s\n", argv[0], strerror(errno));
            return 1;
        }
        if (!alarm_occured)
            if(!update_and_print_single_stat(&stat, &pkt, &ft))
                return 1;
        while (!alarm_occured && !sigint_occured);
        alarm_occured = false;
    }
    print_stat(&stat, &ft);
    return 0;
}