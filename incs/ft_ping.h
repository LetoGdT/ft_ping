#ifndef FT_PING_H
# define FT_PING_H
# include <sys/types.h>

# define TIME_ERROR "Error when retrieving the time\n"

struct __attribute__((packed)) s_icmp_pkt {
    uint8_t        type;
    uint8_t        code;
    uint16_t       checksum;
    uint16_t       id;
    uint16_t       sequence;
    struct timeval timestamp;
};

struct s_icmp_stat {
    int number_of_elements;
    double sum;
    double sum_of_squared;
    double average;
    double mdev;
    double min;
    double max;
};

struct s_ft_ping {
    uint16_t icmp_seq ;
    char *hostname;
    char hostaddress[INET_ADDRSTRLEN];
    int sockfd;
    struct sockaddr serv_addr;
    struct timeval start_time;
    struct timeval end_time;
};

void compute_checksum(unsigned char * ICMP_header, size_t size);
int fill_icmp_pkt(struct s_icmp_pkt *pkt, int icmp_seq);
void sigkill_handler(int sig);
void alarm_handler(int sig);
void initialize_stat(struct s_icmp_stat * stat);
int update_and_print_single_stat(struct s_icmp_stat *stat, struct s_icmp_pkt * const pkt, struct s_ft_ping * ft);
void print_stat(struct s_icmp_stat * stat, struct s_ft_ping const * ft);
int dns_lookup(struct s_ft_ping *ft);

#endif