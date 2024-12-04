#ifndef FT_PING_H
# define FT_PING_H
# include <sys/types.h>

# define TIME_ERROR "Error when retrieving the time\n"
# define RECVD_PKT_MAX_SIZE 60 + 20 + sizeof(struct s_icmp_pkt)

struct __attribute__((packed)) s_icmp_pkt {
    uint8_t        type;
    uint8_t        code;
    uint16_t       checksum;
    uint16_t       id;
    uint16_t       sequence;
    struct timeval timestamp;
};

struct s_icmp_stat {
    int     number_of_elements;
    double  sum;
    double  sum_of_squared;
    double  average;
    double  mdev;
    double  min;
    double  max;
};

struct s_ft_ping {
    char *          prog_name;
    bool            is_verbose;
    char *          hostname;
    char            hostaddress[INET_ADDRSTRLEN];
    int             sockfd;
    struct sockaddr serv_addr;
    struct timeval  start_time;
    struct timeval  end_time;
    uint16_t        icmp_seq;
    uint8_t         TTL;
    uint            error_count;
};

int  parse_arguments(int argc, char ** argv, struct s_ft_ping * ft);
void compute_icmp_checksum(unsigned char * ICMP_header, size_t size);
int  verify_ip_checksum(void *ip_packet);
int  fill_icmp_pkt(struct s_icmp_pkt *pkt, int icmp_seq);
void sigkill_handler(int sig);
void initialize_stat(struct s_icmp_stat * stat);
int  initialize_ping(struct s_ft_ping * ft, char * prog_name);
int  open_socket(struct s_ft_ping * ft);
int  update_and_print_single_stat(struct s_icmp_stat *stat, struct s_icmp_pkt * const pkt, struct s_ft_ping * ft);
void print_stat(struct s_icmp_stat * stat, struct s_ft_ping const * ft);
int  dns_lookup(struct s_ft_ping *ft);
int  ping_single_loop(struct s_ft_ping * ft, struct s_icmp_pkt * pkt, struct s_icmp_stat * stat);
void print_initial_message(struct s_ft_ping * ft);
int  validate_packet(char * const raw_pkt, struct s_icmp_pkt * pkt, struct s_ft_ping * ft);

#endif