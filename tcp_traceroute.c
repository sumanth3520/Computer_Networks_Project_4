/*
 * tcp_traceroute.c
 *
 * TCP-based traceroute using raw sockets (Linux).
 *
 * Requirements satisfied:
 *  - Uses raw sockets (IPPROTO_TCP + IPPROTO_ICMP)
 *  - Sends TCP SYN probes
 *  - Uses only socket API (socket, sendto, recvfrom, select)
 *  - Measures 3 probes per hop
 *  - Command-line interface:
 *        tcp_traceroute [-m MAX_HOPS] [-p DST_PORT] -t TARGET
 *  - Output similar to traceroute, with hostname (IP) and RTT per probe
 *
 * Usage:
 *   $ sudo ./tcp_traceroute -m 10 -p 80 -t www.google.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#define PROBES_PER_HOP     3
#define DEFAULT_PORT       80
#define DEFAULT_MAX_HOPS   30
#define SEND_BUF_SIZE      60

/* ---------- checksum helpers ---------- */

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t tcp_len;
};

/* diff in ms */
double time_diff_ms(struct timeval *start, struct timeval *end) {
    double s = start->tv_sec * 1000.0 + start->tv_usec / 1000.0;
    double e = end->tv_sec * 1000.0 + end->tv_usec / 1000.0;
    return e - s;
}

void print_usage(const char *prog) {
    fprintf(stderr,
        "usage: %s [-m MAX_HOPS] [-p DST_PORT] -t TARGET\n"
        "\n"
        "optional arguments:\n"
        "  -h, --help       show this help message and exit\n"
        "  -m MAX_HOPS      Max hops to probe (default = 30)\n"
        "  -p DST_PORT      TCP destination port (default = 80)\n"
        "  -t TARGET        Target domain or IP\n",
        prog
    );
}

/* ---------- main ---------- */

int main(int argc, char *argv[]) {
    int max_hops = DEFAULT_MAX_HOPS;
    int dest_port = DEFAULT_PORT;
    const char *target = NULL;

    /* ----- parse args with getopt ----- */
    int opt;
    while ((opt = getopt(argc, argv, "hm:p:t:")) != -1) {
        switch (opt) {
        case 'h':
            print_usage(argv[0]);
            return 0;
        case 'm':
            max_hops = atoi(optarg);
            if (max_hops <= 0) {
                fprintf(stderr, "Error: MAX_HOPS must be > 0\n");
                return 1;
            }
            break;
        case 'p':
            dest_port = atoi(optarg);
            if (dest_port <= 0 || dest_port > 65535) {
                fprintf(stderr, "Error: DST_PORT must be between 1 and 65535\n");
                return 1;
            }
            break;
        case 't':
            target = optarg;
            break;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    if (target == NULL) {
        fprintf(stderr, "Error: TARGET is required (-t)\n\n");
        print_usage(argv[0]);
        return 1;
    }

    /* ----- resolve target ----- */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo(target, NULL, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return 1;
    }

    struct sockaddr_in dest;
    memcpy(&dest, res->ai_addr, sizeof(struct sockaddr_in));
    freeaddrinfo(res);

    char dest_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest.sin_addr, dest_ip_str, sizeof(dest_ip_str));

    /* ----- figure out our source IP via a dummy UDP connect ----- */
    int tmp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (tmp_sock < 0) {
        perror("socket");
        return 1;
    }
    dest.sin_port = htons(dest_port);
    if (connect(tmp_sock, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        perror("connect (for source IP discovery)");
        close(tmp_sock);
        return 1;
    }
    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);
    if (getsockname(tmp_sock, (struct sockaddr *)&src, &src_len) < 0) {
        perror("getsockname");
        close(tmp_sock);
        return 1;
    }
    close(tmp_sock);

    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src.sin_addr, src_ip_str, sizeof(src_ip_str));

    printf("traceroute to %s (%s), %d hops max, TCP SYN to port %d\n",
           target, dest_ip_str, max_hops, dest_port);

    /* ----- raw sockets ----- */
    /* send: raw TCP with IP header */
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (send_sock < 0) {
        perror("socket send_sock");
        return 1;
    }
    int on = 1;
    if (setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(send_sock);
        return 1;
    }

    /* recv ICMP (time exceeded) */
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) {
        perror("socket icmp_sock");
        close(send_sock);
        return 1;
    }

    /* recv TCP (SYN/ACK) */
    int tcp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (tcp_sock < 0) {
        perror("socket tcp_sock");
        close(send_sock);
        close(icmp_sock);
        return 1;
    }

    int reached = 0;
    uint16_t ip_id = 54321;
    uint32_t base_seq = 0x1000;

    for (int ttl = 1; ttl <= max_hops && !reached; ttl++) {
        printf("%2d ", ttl);
        fflush(stdout);

        for (int probe = 0; probe < PROBES_PER_HOP; probe++) {
            unsigned char buf[SEND_BUF_SIZE];
            memset(buf, 0, sizeof(buf));

            struct ip *iph = (struct ip *)buf;
            struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct ip));

            /* ----- build IP header ----- */
            iph->ip_hl = 5;
            iph->ip_v = 4;
            iph->ip_tos = 0;
            iph->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
            iph->ip_id = htons(ip_id++);
            iph->ip_off = 0;
            iph->ip_ttl = ttl;
            iph->ip_p = IPPROTO_TCP;
            iph->ip_sum = 0;
            iph->ip_src = src.sin_addr;
            iph->ip_dst = dest.sin_addr;
            iph->ip_sum = checksum((unsigned short *)iph, sizeof(struct ip));

            /* ----- build TCP header ----- */
            uint16_t sport = 40000 + ttl * 10 + probe;  /* vary sport by ttl/probe */
            tcph->th_sport = htons(sport);
            tcph->th_dport = htons(dest_port);
            tcph->th_seq = htonl(base_seq + ttl * 100 + probe);
            tcph->th_ack = 0;
            tcph->th_off = 5;
            tcph->th_flags = TH_SYN;
            tcph->th_win = htons(65535);
            tcph->th_sum = 0;
            tcph->th_urp = 0;

            /* TCP checksum with pseudo header */
            struct pseudo_header psh;
            psh.src_addr = iph->ip_src.s_addr;
            psh.dst_addr = iph->ip_dst.s_addr;
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_len = htons(sizeof(struct tcphdr));

            unsigned char pseudo_buf[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
            memcpy(pseudo_buf, &psh, sizeof(psh));
            memcpy(pseudo_buf + sizeof(psh), tcph, sizeof(struct tcphdr));
            tcph->th_sum = checksum((unsigned short *)pseudo_buf, sizeof(pseudo_buf));

            struct sockaddr_in send_addr;
            memset(&send_addr, 0, sizeof(send_addr));
            send_addr.sin_family = AF_INET;
            send_addr.sin_addr = dest.sin_addr;

            struct timeval start, end;
            gettimeofday(&start, NULL);

            ssize_t sent = sendto(send_sock, buf,
                                  sizeof(struct ip) + sizeof(struct tcphdr),
                                  0, (struct sockaddr *)&send_addr,
                                  sizeof(send_addr));
            if (sent < 0) {
                perror("sendto");
                printf("* ");
                fflush(stdout);
                continue;
            }

            /* wait on ICMP/TCP replies */
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(icmp_sock, &readfds);
            FD_SET(tcp_sock, &readfds);
            int max_fd = (icmp_sock > tcp_sock ? icmp_sock : tcp_sock) + 1;

            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;

            int sel = select(max_fd, &readfds, NULL, NULL, &tv);
            if (sel < 0) {
                perror("select");
                printf("* ");
                fflush(stdout);
                continue;
            } else if (sel == 0) {
                /* timeout */
                printf("* ");
                fflush(stdout);
                continue;
            }

            int got_something = 0;

            /* ----- check TCP (SYN/ACK from destination) ----- */
            if (FD_ISSET(tcp_sock, &readfds)) {
                unsigned char rbuf[1500];
                struct sockaddr_in raddr;
                socklen_t rlen = sizeof(raddr);
                ssize_t rcv = recvfrom(tcp_sock, rbuf, sizeof(rbuf), 0,
                                       (struct sockaddr *)&raddr, &rlen);
                if (rcv > 0) {
                    struct ip *rip = (struct ip *)rbuf;
                    int ip_hdr_len = rip->ip_hl * 4;
                    if (rip->ip_p == IPPROTO_TCP &&
                        rcv >= ip_hdr_len + (int)sizeof(struct tcphdr)) {

                        struct tcphdr *rtcp =
                            (struct tcphdr *)(rbuf + ip_hdr_len);

                        if (rip->ip_src.s_addr == dest.sin_addr.s_addr &&
                            ntohs(rtcp->th_dport) == sport &&
                            (rtcp->th_flags & (TH_SYN | TH_ACK)) ==
                            (TH_SYN | TH_ACK)) {

                            gettimeofday(&end, NULL);
                            double rtt = time_diff_ms(&start, &end);

                            char hop_ip[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &rip->ip_src, hop_ip,
                                      sizeof(hop_ip));

                            char host_buf[NI_MAXHOST];
                            if (getnameinfo((struct sockaddr *)&raddr,
                                            sizeof(raddr),
                                            host_buf,
                                            sizeof(host_buf),
                                            NULL, 0, 0) == 0) {
                                printf("%s (%s)  %.3f ms  ",
                                       host_buf, hop_ip, rtt);
                            } else {
                                printf("%s (%s)  %.3f ms  ",
                                       hop_ip, hop_ip, rtt);
                            }

                            fflush(stdout);
                            got_something = 1;
                            reached = 1;
                        }
                    }
                }
            }

            /* ----- check ICMP (time exceeded from intermediate router) ----- */
            if (!got_something && FD_ISSET(icmp_sock, &readfds)) {
                unsigned char rbuf[1500];
                struct sockaddr_in raddr;
                socklen_t rlen = sizeof(raddr);
                ssize_t rcv = recvfrom(icmp_sock, rbuf, sizeof(rbuf), 0,
                                       (struct sockaddr *)&raddr, &rlen);
                if (rcv > 0) {
                    struct ip *rip = (struct ip *)rbuf;
                    int ip_hdr_len = rip->ip_hl * 4;
                    struct icmp *ricmp =
                        (struct icmp *)(rbuf + ip_hdr_len);

                    if (ricmp->icmp_type == ICMP_TIME_EXCEEDED) {
                        /* inner IP + TCP from original packet */
                        unsigned char *inner =
                            (unsigned char *)ricmp->icmp_data;
                        struct ip *inner_ip = (struct ip *)inner;
                        int inner_ip_hl = inner_ip->ip_hl * 4;

                        if (inner_ip->ip_p == IPPROTO_TCP &&
                            inner_ip->ip_dst.s_addr == dest.sin_addr.s_addr) {

                            struct tcphdr *inner_tcp =
                                (struct tcphdr *)(inner + inner_ip_hl);

                            if (ntohs(inner_tcp->th_dport) == dest_port) {
                                gettimeofday(&end, NULL);
                                double rtt = time_diff_ms(&start, &end);

                                char hop_ip[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &rip->ip_src, hop_ip,
                                          sizeof(hop_ip));

                                char host_buf[NI_MAXHOST];
                                if (getnameinfo((struct sockaddr *)&raddr,
                                                sizeof(raddr), host_buf,
                                                sizeof(host_buf),
                                                NULL, 0, 0) == 0) {
                                    printf("%s (%s)  %.3f ms  ",
                                           host_buf, hop_ip, rtt);
                                } else {
                                    printf("%s (%s)  %.3f ms  ",
                                           hop_ip, hop_ip, rtt);
                                }

                                fflush(stdout);
                                got_something = 1;
                            }
                        }
                    }
                }
            }

            if (!got_something) {
                printf("* ");
                fflush(stdout);
            }
        }

        printf("\n");
        if (reached)
            break;
    }

    close(send_sock);
    close(icmp_sock);
    close(tcp_sock);

    return 0;
}
