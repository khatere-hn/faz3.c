#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <assert.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>


int packet_ping = 64;

#define PORT_NO 0
#define RATE_SLEEP 1000000
int loop_ping = 4;
int ttl_start = 1;
int ttl_final = 6;
bool trace_forcing = true;

const int packet_minimum_size = 10;

int timeout_Recevie = 1;
int max_try = 3;


struct ping_pkt {
    char *message;
    struct icmphdr header;
};

int aoti_to_int(char *s) {
    int i, j = 0;
    for (i = 0; s[i] >= '0' && s[i] <= '9'; i++) {
        j = 10 * j + (s[i] - '0');
    }
    return j;
}

unsigned short check_sum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int final_sum = 0;
    unsigned short result;

    for (final_sum = 0; len > 1; len -= 2)
        final_sum += *buf++;
    if (len == 1)
        final_sum += *(unsigned char *) buf;
    final_sum = (final_sum >> 16) + (final_sum & 0xFFFF);
    final_sum += (final_sum >> 16);
    result = ~final_sum;
    return result;
}


char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con) {
    printf("DNS Resolving is Processing\n");
    struct hostent *host_entity;
    char *ip = (char *) malloc(NI_MAXHOST * sizeof(char));

    if ((host_entity = gethostbyname(addr_host)) == NULL) {
        return NULL;
    }

    strcpy(ip, inet_ntoa(*(struct in_addr *)
            host_entity->h_addr));

    (*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_port = htons(PORT_NO);
    (*addr_con).sin_addr.s_addr = *(long *) host_entity->h_addr;

    return ip;

}

char *dns_resolve(char *ip_addr) {
    struct sockaddr_in address;
    socklen_t len;
    char buf[NI_MAXHOST], *ret_buf;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip_addr);
    len = sizeof(struct sockaddr_in);

    if (getnameinfo((struct sockaddr *) &address, len, buf,
                    sizeof(buf), NULL, 0, NI_NAMEREQD)) {
        return NULL;
    }
    ret_buf = (char *) malloc((strlen(buf) + 1) * sizeof(char));
    strcpy(ret_buf, buf);
    return ret_buf;
}

void request_ping(int ping_sockfd, struct sockaddr_in *ping_addr,
                  char *ping_dom, char *ping_ip, char *rev_host, int ttl_val) {

    int msg_count = 0;
    int i;
    int addr_len;
    int flag = 1;
    int msg_received_count = 0;
    int number_of_tries = 0;

    struct ping_pkt pckt;

    struct timespec time_start, time_end, tfs, tfe;
    long double message_rtt = 0;
    long double message_all = 0;
    struct timeval eval_final;
    eval_final.tv_sec = timeout_Recevie;
    eval_final.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &tfs);

    if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
        printf("\nSetting socket options to TTL failed!\n");
        return;
    }

    loop_ping = max_try;
    while (loop_ping) {

        char *reverse_hostname;
        loop_ping--;
        number_of_tries++;

        flag = 1;
        bzero(&pckt, sizeof(pckt));

        pckt.header.type = ICMP_ECHO;
        pckt.header.un.echo.id = getpid();

        int packet_size = packet_ping - sizeof(struct icmphdr);
        pckt.message = malloc(packet_size);

        if (pckt.message == NULL) {
            fputs("memory allocation for message failed", stderr);
            exit(EXIT_FAILURE);
        }

        for (i = 0; i < packet_size - 1; i++)
            pckt.message[i] = i % 10 + '0';
        pckt.message[i] = 0;
        pckt.header.un.echo.sequence = msg_count++;
        pckt.header.checksum = check_sum(&pckt, sizeof(pckt));
        usleep(RATE_SLEEP);
        clock_gettime(CLOCK_MONOTONIC, &time_start);
        if (sendto(ping_sockfd, &pckt, sizeof(pckt), 0,
                   (struct sockaddr *) ping_addr,
                   sizeof(*ping_addr)) <= 0) {
            printf("\nPacket Sending Failed!\n");
            flag = 0;
        }
        struct sockaddr_in r_addr;
        addr_len = sizeof(r_addr);

        if (recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr *) &r_addr, &addr_len) <= 0 &&
            msg_count > 1) {
            printf("\nPacket receive failed!\n");
        } else {
            clock_gettime(CLOCK_MONOTONIC, &time_end);

            double timeElapsed = ((double) (time_end.tv_nsec - time_start.tv_nsec)) / 1000000.0;
            message_rtt = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed;

            if (flag) {
                if (!(pckt.header.type == 69 && pckt.header.code == 0)) {
                    printf("Error..Packet received with ICMP type %d code %d\n", pckt.header.type, pckt.header.code);
                } else {
                    loop_ping = 0;
                    reverse_hostname = dns_resolve(inet_ntoa(r_addr.sin_addr));
                    printf("HOP<%d> <==> <%s>(reverse hosntame = <%s>) in %Lfms after %d tries \n",
                           ttl_val, inet_ntoa(r_addr.sin_addr), reverse_hostname, message_rtt, number_of_tries);
                    msg_received_count++;
                }
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &tfe);

}

void intHandler(int dummy) {
    loop_ping = 0;
    trace_forcing = false;
}

int main(int argc, char *argv[]) {
    int sockfd;
    char *ip_addr, *reverse_hostname;
    struct sockaddr_in addr_con;
    int addrlen;
    __attribute__((unused)) char net_buf[NI_MAXHOST];

    in_port_t server_port;

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        printf(" -m or --maxtry : MAX TRY\n");
        printf(" -b or --bttl: beginning ttl value\n");
        printf(" -f or --fttl: final ttl value\n");
        printf(" -p or --port: sending port number\n");
        printf(" -t or --timeout: timeout(maximum waiting time)\n");
        printf(" -s or --size: size of each packet\n");
        return 0;
    }


    if (argc < 3) {
        printf("\nFormat %s <address> <options>\n", argv[0]);
        printf("use -h to see more \n");
        return 0;
    }


    for (int i = 1; i < argc; i++) {

        printf("\n\ni=%d\n", i);
        printf("argv%d=%s\n", i, argv[i]);

        if (i + 1 != argc) {
            if (strcmp(argv[i], "--bttl") == 0 || strcmp(argv[i], "-b") == 0) {
                ttl_start = aoti_to_int(argv[i + 1]);
                printf("ttl_start set %d\n", ttl_start);
                i++;    // Move to the next flag
            } else if (strcmp(argv[i], "--fttl") == 0 || strcmp(argv[i], "-f") == 0) {
                ttl_final = aoti_to_int(argv[i + 1]);
                printf("ttl_final set to %d\n", ttl_final);
                i++;    // Move to the next flag
            } else if (strcmp(argv[i], "--port") == 0 || strcmp(argv[i], "-p") == 0) {
                server_port = aoti_to_int(argv[i + 1]);
                addr_con.sin_port = server_port;
                printf("PORT set to %d\n", server_port);
                i++;    // Move to the next flag
            } else if (strcmp(argv[i], "--timeout") == 0 || strcmp(argv[i], "-t") == 0) {
                timeout_Recevie = aoti_to_int(argv[i + 1]);
                printf(" TIMEOUT set to %d\n", timeout_Recevie);
                i++;    // Move to the next flag
            } else if (strcmp(argv[i], "--size") == 0 || strcmp(argv[i], "-s") == 0) {
                int input_packet_size = aoti_to_int(argv[i + 1]);
                if (input_packet_size > packet_minimum_size) {
                    packet_ping = input_packet_size;
                }
                printf("packetsize chosen=%d\n", packet_ping);
                i++;    // Move to the next flag

            } else if (strcmp(argv[i], "--maxtry") == 0 || strcmp(argv[i], "-m") == 0) {
                max_try = aoti_to_int(argv[i + 1]);
                printf("MAX TRY set to %d\n", max_try);
                i++;    // Move to the next flag
            }


        }
    }


    ip_addr = dns_lookup(argv[1], &addr_con);
    if (ip_addr == NULL) {
        printf("\nDNS lookup failed! Could not resolve hostname!\n");
        return 0;
    }

    reverse_hostname = dns_resolve(ip_addr);
    printf("\nTrying to connect to '%s' IP: %s\n", argv[1], ip_addr);
    printf("\nReverse Lookup domain: %s", reverse_hostname);

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        printf("\nSocket file descriptor not received!!\n");
        return 0;
    } else {
        printf("\nSocket file descriptor %d received\n", sockfd);
    }

    signal(SIGINT, intHandler);
    for (int ttl = ttl_start; ttl <= ttl_final && trace_forcing; ttl++) {
        request_ping(sockfd, &addr_con, reverse_hostname, ip_addr, argv[1], ttl);
    }
    return 0;
}
