#ifndef FT_PING_H
# define FT_PING_H
# include <signal.h>
# include <sys/types.h>

# define RECVD_PKT_MAX_SIZE 60 + 20 + 2 * sizeof(struct s_icmp_pkt)
// Cycle time in ms
# define CYCLE_TIME 1000
# define DATA_WIDTH 16
# define DFLT_DATA "pouet"
# define TIME_ERROR "Error when retrieving the time\n"
# define SEND_ERROR "%s: Cannot send packets over socket: %s\n"
# define PRINT_STRERROR "%s: %s\n", ft->prog_name, strerror(errno)
# define DEST_UNREACHABLE "The destination host or network is unreachable\n"
# define TTL_EXP "Time to live exceeded\n"
# define HDR_ERR "A problem occured in the header of the packet\n"
# define DFLT_ERR "An error occured\n"
# define DNS_LKUP_ERR "%s: %s: Name or service not known\n", ft->prog_name, ft->canon_name
# define SOCK_OPEN_ERR "%s: Cannot open socket: %s\n", ft->prog_name, strerror(errno)
# define IP_CHKSUM_ERR "IP header checksum was wrong"
# define ICMP_CHKSUM_ERR "ICMP header checksum was wrong"
# define ARG_NEEDED "%s: option requires an argument -- '%c'\n", argv[0], optopt
# define INVLD_ARG "%s: invalid option -- '%c'\n", argv[0], optopt
# define MISSING_DEST "%s: usage error: Destination address required\n", argv[0]
# define USAGE "Usage\n\
  ft_ping [options] <destination>\n\
\n\
Options:\n\
  <destination>  dns name or ip address\n\
  -a             use audible ping\n\
  -c <count>     stop after <count> replies\n\
  -i <interval>  seconds between sending each packet\n\
  -h             print help and exit\n\
  -p <pattern>   contents of padding byte\n\
  -t <ttl>       define time to live\n\
  -v             verbose output\n\
For more detail, ask Léto\n"

extern volatile sig_atomic_t sigint_occured;

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
    char           data[DATA_WIDTH];
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
    char *          canon_name;
    char *          hostname;
    char            hostaddress[INET_ADDRSTRLEN];
    int             sockfd;
    struct sockaddr serv_addr;
    struct timeval  start_time;
    struct timeval  end_time;
    uint16_t        icmp_seq;
    uint8_t         TTL;
    uint            error_count;
    int             TTL_to_send;
    int             number_of_requests_to_send;
    long int        cycle_time;
    bool            bell;
    bool            use_pattern;
    unsigned char   pattern;
};

int   parse_arguments(int argc, char ** argv, struct s_ft_ping * ft);
void  compute_icmp_checksum(unsigned char * ICMP_header, size_t size);
int   verify_ip_checksum(void *ip_packet);
int   fill_icmp_pkt(struct s_icmp_pkt *pkt, struct s_ft_ping const * ft);
void  sigkint_handler(int sig);
void  initialize_stat(struct s_icmp_stat * stat);
int   initialize_ping(struct s_ft_ping * ft, char * prog_name);
int   open_socket(struct s_ft_ping * ft);
int   update_and_print_single_stat(struct s_icmp_stat *stat, struct s_icmp_pkt * const pkt, struct s_ft_ping * ft);
void  print_stat(struct s_icmp_stat * stat, struct s_ft_ping const * ft);
int   dns_lookup(struct s_ft_ping *ft);
char* reverse_dns_lookup(char * const raw_pkt);
int   ping_single_loop(struct s_ft_ping * ft, struct s_icmp_pkt * pkt, struct s_icmp_stat * stat);
void  print_initial_message(struct s_ft_ping * ft);
int   validate_packet(char * const raw_pkt, struct s_icmp_pkt * pkt, struct s_ft_ping * ft);
int   read_loop(struct s_ft_ping * ft, struct s_icmp_pkt * pkt, struct s_icmp_stat * stat, struct timeval * loop_start);
void  print_error_code(char * const raw_pkt, enum error_code error_code, struct s_icmp_pkt * const pkt, struct s_ft_ping * const ft);

#endif