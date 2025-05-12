/**
 * ping.c — simple ping utility with built-in ICMP flood detection
 *
 * Usage:
 *   sudo ./ping <hostname>
 *
 * Compile:
 *   gcc -std=c11 -O2 -pthread -o ping ping.c
 *
 * Notes:
 *   - Requires root (or CAP_NET_RAW) to open a raw ICMP socket.
 *   - Press Ctrl+C to stop; will print summary and exit cleanly.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/time.h>

#define PKT_SIZE          64      /* total ICMP packet size */
#define TIMEOUT_SEC       5       /* recv timeout */
#define MONITOR_INTERVAL  5       /* seconds between ICMP stats checks */
#define FLOOD_THRESHOLD   100UL   /* packets/sec threshold for alert */

int               sock         = -1;
int               tx_count     = 0;
int               rx_count     = 0;
unsigned int      dest_addr    = 0;

/* Flag to control monitor thread */
static atomic_bool keep_running = ATOMIC_VAR_INIT(true);
static pthread_t    monitor_thread;

/* Compute Internet checksum */
unsigned short in_cksum(unsigned short *addr, int count) {
    unsigned long sum = 0;
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(unsigned char *)addr;
    }
    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/* Read the “InMsgs” counter from /proc/net/snmp */
static unsigned long read_icmp_inmsgs(void) {
    FILE *f = fopen("/proc/net/snmp", "r");
    if (!f) return 0;

    char line[256];
    bool seen_header = false;
    unsigned long inmsgs = 0;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Icmp:", 5) == 0) {
            if (!seen_header) {
                /* first "Icmp:" line is header */
                seen_header = true;
            } else {
                /* second "Icmp:" line: parse first field */
                if (sscanf(line + 5, "%lu", &inmsgs) == 1) {
                    break;
                }
            }
        }
    }

    fclose(f);
    return inmsgs;
}

/* Monitor thread: check for ICMP flood spikes */
static void *icmp_monitor_thread(void *arg) {
    (void)arg;
    unsigned long prev = read_icmp_inmsgs();

    while (atomic_load(&keep_running)) {
        sleep(MONITOR_INTERVAL);
        unsigned long now   = read_icmp_inmsgs();
        unsigned long delta = (now >= prev ? now - prev : 0);

        if (delta > FLOOD_THRESHOLD) {
            fprintf(stderr,
                "[ICMP ALERT] %lu InMsgs in last %d sec (threshold=%lu)\n",
                delta, MONITOR_INTERVAL, FLOOD_THRESHOLD);
        }
        prev = now;
    }
    return NULL;
}

/* SIGINT/SIGTERM handler: stop monitor and print summary */
static void cleanup(int sig) {
    (void)sig;
    atomic_store(&keep_running, false);

    printf("\n--- %s ping statistics ---\n",
           inet_ntoa(*(struct in_addr *)&dest_addr));

    float loss = 0.0f;
    if (tx_count > 0) {
        loss = 100.0f * (tx_count - rx_count) / tx_count;
    }
    printf("%d packets transmitted, %d received, %.1f%% packet loss\n",
           tx_count, rx_count, loss);

    if (sock >= 0) {
        close(sock);
    }

    /* Give monitor thread a moment to exit */
    sleep(1);
    exit(EXIT_SUCCESS);
}

/* Initialize raw ICMP socket with recv timeout */
int init_socket(void) {
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0) {
        perror("socket");
        fprintf(stderr, "-> Must run as root or have CAP_NET_RAW\n");
        return -1;
    }

    struct timeval tv_out = {
        .tv_sec  = TIMEOUT_SEC,
        .tv_usec = 0
    };
    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        close(s);
        return -1;
    }

    return s;
}

/* Fill sendbuf with ICMP echo request */
void prep_packet(char *sendbuf, int seq) {
    memset(sendbuf, 0, PKT_SIZE);
    struct icmp *pkt = (struct icmp *)sendbuf;

    pkt->icmp_type = ICMP_ECHO;
    pkt->icmp_code = 0;
    pkt->icmp_id   = getpid() & 0xFFFF;
    pkt->icmp_seq  = seq;
    memset(pkt->icmp_data, 0x42,
           PKT_SIZE - (int)sizeof(struct icmp));

    pkt->icmp_cksum = 0;
    pkt->icmp_cksum = in_cksum((unsigned short *)pkt, PKT_SIZE);
}

/* Send one ICMP packet */
int send_packet(int sock, char *sendbuf, struct sockaddr_in *dest) {
    int bytes = sendto(sock, sendbuf, PKT_SIZE, 0,
                       (struct sockaddr *)dest, sizeof(*dest));
    if (bytes < 0) {
        perror("sendto");
    }
    return bytes;
}

/* Receive one ICMP reply (with timeout) */
int receive_packet(int sock, char *recvbuf, size_t bufsize,
                   struct sockaddr_in *from) {
    socklen_t fromlen = sizeof(*from);
    return recvfrom(sock, recvbuf, bufsize, 0,
                    (struct sockaddr *)from, &fromlen);
}

/* Process a valid ICMP echo reply */
void process_reply(char *buf, int bytes,
                   struct sockaddr_in *from,
                   int seq,
                   struct timeval *tv_start,
                   struct timeval *tv_end)
{
    struct ip   *ip_hdr = (struct ip *)buf;
    int          ip_len = ip_hdr->ip_hl << 2;
    struct icmp *icmp_reply =
        (struct icmp *)(buf + ip_len);

    if (icmp_reply->icmp_type == ICMP_ECHOREPLY &&
        icmp_reply->icmp_id   == (getpid() & 0xFFFF))
    {
        rx_count++;
        double rtt = (tv_end->tv_sec  - tv_start->tv_sec ) * 1000.0 +
                     (tv_end->tv_usec - tv_start->tv_usec) / 1000.0;

        printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
               bytes - ip_len,
               inet_ntoa(from->sin_addr),
               icmp_reply->icmp_seq,
               ip_hdr->ip_ttl,
               rtt);
    }
}

/* Main ping/send & receive loop */
int ping_loop(int sock, struct sockaddr_in *dest) {
    char           sendbuf[PKT_SIZE];
    char           recvbuf[PKT_SIZE + sizeof(struct ip)];
    struct sockaddr_in from;
    struct timeval   tv_start, tv_end;

    while (1) {
        prep_packet(sendbuf, tx_count++);
        gettimeofday(&tv_start, NULL);

        if (send_packet(sock, sendbuf, dest) < 0) {
            continue;
        }

        int bytes = receive_packet(sock, recvbuf,
                                   sizeof(recvbuf), &from);
        gettimeofday(&tv_end, NULL);

        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("Request timeout for icmp_seq=%d\n",
                       tx_count - 1);
            } else {
                perror("recvfrom");
            }
        } else {
            process_reply(recvbuf, bytes, &from,
                          tx_count - 1, &tv_start, &tv_end);
        }

        sleep(1);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <hostname>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (inet_pton(AF_INET, argv[1], &dest_addr) <= 0) {
        fprintf(stderr, "Invalid address: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    /* Install clean shutdown handlers */
    struct sigaction sa = {
        .sa_handler = cleanup
    };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sock = init_socket();
    if (sock < 0) {
        return EXIT_FAILURE;
    }

    /* Start ICMP-flood monitor thread */
    if (pthread_create(&monitor_thread, NULL,
                       icmp_monitor_thread, NULL) == 0)
    {
        pthread_detach(monitor_thread);
    } else {
        perror("pthread_create");
    }

    struct sockaddr_in dest = {0};
    dest.sin_family      = AF_INET;
    dest.sin_addr.s_addr = dest_addr;

    printf("PING %s (%s): %d data bytes\n",
           argv[1],
           inet_ntoa(*(struct in_addr *)&dest_addr),
           PKT_SIZE - (int)sizeof(struct icmp));

    return ping_loop(sock, &dest);
}