#ifndef FT_PING_H
# define FT_PING_H
# include <time.h>
# include <sys/types.h>

# define TIME_ERROR "Error when retrieving the time\n"

struct __attribute__((packed)) s_icmp_pkt {
    uint8_t     type;
    uint8_t     code;
    uint16_t    checksum;
    uint16_t    id;
    uint16_t    sequence;
    time_t      timestamp;
};

struct s_icmp_stat {
    int number_of_elements;
    double sum;
    double sum_of_squared;
    double average;
    double mdev;
};

void compute_checksum(unsigned char * ICMP_header, size_t size);
void fill_icmp_pkt(struct s_icmp_pkt *pkt, int icmp_seq);
void sigkill_handler(int sig);
void alarm_handler(int sig);
void update_stat(struct s_icmp_stat *stat, struct s_icmp_pkt * const pkt);

#endif