#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdbool.h>
#define TTL 255 // check this value

volatile sig_atomic_t alarm_occured = false;
volatile sig_atomic_t sigkill_occured = false;

void alarm_handler(int sig){
    alarm_occured = true;
}

void sigkill_handler(int sig){
    sigkill_occured = true;
}

int main(int argc, char** argv){
    int icmp_seq = 0;

    // parse arguments
    signal(SIGALRM, alarm_handler);
    signal(SIGKILL, sigkill_handler);
    // make dns query
    // open socket with datagram protocol
    while (!sigkill_occured) {
        // send echo request, with timestamp in data (ICMP type 8 code 0)
        alarm(1);
        // make blocking read on socket waiting for echo reply (ICMP type 0 code 0)
        if (!alarm_occured) {
            // print info on received icmp packet
                // 64 bytes from par21s20-in-f14.1e100.net (142.250.179.110): icmp_seq=5 ttl=113 time=7.27 ms
        }
        alarm_occured = false;
    }
    // print info on ping instance
        // --- google.com ping statistics ---
        // 5 packets transmitted, 5 received, 0% packet loss, time 4006ms
        // rtt min/avg/max/mdev = 6.912/7.145/7.330/0.146 ms
    return 0;
}