#include <unistd.h>
#include <signal.h>e
#include <arpa/nameser.h>
#include <stdbool.h>
#include <resolv.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include "ft_ping.h"
#define TTL 255 // check this value

volatile sig_atomic_t alarm_occured = false;
volatile sig_atomic_t sigkill_occured = false;

void alarm_handler(int sig){
    alarm_occured = true;
}

void sigkill_handler(int sig){
    sigkill_occured = true;
}

void fill_icmp_pkt(struct s_icmp_pkt *pkt, int icmp_seq){
    time_t t;

    t = time(NULL);
    if (t == -1){
        printf(TIME_ERROR);
        return -1;
    }
    bzero(pkt, sizeof(struct s_icmp_pkt));
    pkt->type = 8;
    pkt->code = 0;
    pkt->id = getpid();
    pkt->sequence = icmp_seq;
    pkt->timestamp = t;
    compute_checksum((unsigned char*)pkt, sizeof(struct s_icmp_pkt));
}

void update_stat(struct s_icmp_stat *stat, struct s_icmp_pkt * const pkt){
    time_t current_time;
    double time_diff;

    current_time = time(NULL);
    if (current_time == -1) {
        printf(TIME_ERROR);
        return 1;
    }
    time_diff = difftime(current_time, pkt->timestamp);
    stat->sum += time_diff;
    stat->sum_of_squared += pow(time_diff, 2);
    stat->number_of_elements++;
}

void finalise_stat(struct s_icmp_stat * stat){
    stat->average = stat->sum / stat->number_of_elements;
    stat->mdev = sqrt(stat->sum_of_squared / stat->number_of_elements - pow(stat->average, 2));
}

int main(int argc, char** argv){
    uint16_t icmp_seq = 0;
    char *addr = "1.1.1.1";
    struct sockaddr_in serv_addr;
    struct s_icmp_pkt pkt;
    struct s_icmp_stat stat;
    int sockfd;

    // parse arguments
    signal(SIGALRM, alarm_handler);
    signal(SIGKILL, sigkill_handler);
    // make dns query or parse addr
    if (inet_pton(AF_INET, addr, &serv_addr) != 1) {
        printf("%s: %s: Name or service not known", argv[0], addr);
        return 2;
    }
    // open socket with datagram protocol
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sockfd == -1) {
        printf("%s\n", strerror(errno));
        return 1;
    }
    // Connect socket
    if (connect (sockfd, addr, sizeof(addr)) == -1) {
        printf("%s: %s\n", argv[0], strerror(errno));
        close(sockfd);
        return 1;
    }
    stat.number_of_elements = 0;
    stat.sum = 0;
    stat.sum_of_squared = 0;
    while (!sigkill_occured) {
        fill_icmp_pkt(&pkt, icmp_seq);
        if (send(sockfd, &pkt, sizeof(pkt), 0) == -1) {
            printf("%s: %s\n", argv[0], strerror(errno));
            return 1;
        }
        // send echo request, with timestamp in data (ICMP type 8 code 0)
        alarm(1);
        // make blocking read on socket waiting for echo reply (ICMP type 0 code 0)
        read(sockfd, &pkt, sizeof(pkt));
        if (read )
        if (!alarm_occured) {
            update_stat(&stat, &pkt);
            // print info on received icmp packet
                // 64 bytes from par21s20-in-f14.1e100.net (142.250.179.110): icmp_seq=5 ttl=113 time=7.27 ms
        }
        alarm_occured = false;
        icmp_seq++;
    }
    finalise_stat(&stat);
    // print info on ping instance
        // --- google.com ping statistics ---
        // 5 packets transmitted, 5 received, 0% packet loss, time 4006ms
        // rtt min/avg/max/mdev = 6.912/7.145/7.330/0.146 ms
    return 0;
}