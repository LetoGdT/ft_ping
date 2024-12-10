#ifndef FT_PING_H
# define FT_PING_H
# include <sys/types.h>

# define RECVD_PKT_MAX_SIZE 60 + 20 + 2 * sizeof(struct s_icmp_pkt)
// Cycle time in ms
# define CYCLE_TIME 1000
# define TIME_ERROR "Error when retrieving the time\n"
# define SEND_ERROR "%s: Cannot send packets over socket: %s\n"
# define PRINT_STRERROR "%s: %s\n", ft->prog_name, strerror(errno)
# define DEST_UNREACHABLE "The destination host or network is unreachable\n"
# define TTL_EXP "Time to live exceeded\n"
# define HDR_ERR "A problem occured in the header of the packet\n"
# define DFLT_ERR "An error occured\n"
# define DNS_LKUP_ERR "%s: %s: Name or service not known\n", ft->prog_name, ft->hostname
# define SOCK_OPEN_ERR "%s: Cannot open socket: %s\n", ft->prog_name, strerror(errno)
# define IP_CHKSUM_ERR "IP header checksum was wrong"
# define ICMP_CHKSUM_ERR "ICMP header checksum was wrong"
# define USAGE "%s: Usage: %s archlinux.org [-v]\n", argv[0], argv[0]

enum error_code {
    no_error = 0,
    ip_chksum,
    icmp_chksum,
    not_echo
};

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

int   parse_arguments(int argc, char ** argv, struct s_ft_ping * ft);
void  compute_icmp_checksum(unsigned char * ICMP_header, size_t size);
int   verify_ip_checksum(void *ip_packet);
int   fill_icmp_pkt(struct s_icmp_pkt *pkt, int icmp_seq);
void  sigkill_handler(int sig);
void  initialize_stat(struct s_icmp_stat * stat);
int   initialize_ping(struct s_ft_ping * ft, char * prog_name);
int   open_socket(struct s_ft_ping * ft);
int   update_and_print_single_stat(struct s_icmp_stat *stat, struct s_icmp_pkt * const pkt, struct s_ft_ping * ft);
void  print_stat(struct s_icmp_stat * stat, struct s_ft_ping const * ft);
int   dns_lookup(struct s_ft_ping *ft);
char* reverse_dns_lookup(char * const addr);
int   ping_single_loop(struct s_ft_ping * ft, struct s_icmp_pkt * pkt, struct s_icmp_stat * stat);
void  print_initial_message(struct s_ft_ping * ft);
int   validate_packet(char * const raw_pkt, struct s_icmp_pkt * pkt, struct s_ft_ping * ft);
int   read_loop(struct s_ft_ping * ft, struct s_icmp_pkt * pkt, struct s_icmp_stat * stat, struct timeval * loop_start);
void  print_error_code(char * const raw_pkt, enum error_code error_code, struct s_icmp_pkt * const pkt, struct s_ft_ping * const ft);

#endif