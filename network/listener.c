#include "../include/network/listener.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

char errbuf[PCAP_ERRBUF_SIZE];

struct ethheader
{
    unsigned char ether_dhost[6];   // Target MAC
    unsigned char ether_shost[6];   // Source MAC
    unsigned short ether_type;      // (IPv4: 0x0800)
};

struct ipheader {
    unsigned char iph_ihl:4;        // IP header size
    unsigned char iph_ver:4;        // IP version
    unsigned char iph_tos;          // Service type
    unsigned short iph_len;         // Total height
    unsigned short iph_ident;       // Validation
    unsigned short iph_flag:3;      // Fragmentation flags
    unsigned short iph_offset:13;   // Fragment offset
    unsigned char iph_ttl;          // Time to live
    unsigned char iph_protocol;     // Protocol (TCP=6, UDP=17)
    unsigned short iph_chksum;      // Check
    struct in_addr iph_sourceip;    // Source IP
    struct in_addr iph_destip;      // Target IP
};

struct tcpheader {
    unsigned short tcp_sport;       // Source port
    unsigned short tcp_dport;       // Destination port
    unsigned int tcp_seq;           // Sequence number
    unsigned int tcp_ack;           // Acknowledgment number
    unsigned char tcp_offx2;        // Data offset, reserved
    unsigned char tcp_flags;        // Flags
    unsigned short tcp_win;         // Window
    unsigned short tcp_sum;         // Checksum
    unsigned short tcp_urp;         // Urgent pointer
};

struct udpheader {
    unsigned short udp_sport;       // Source port
    unsigned short udp_dport;       // Destination port
    unsigned short udp_len;         // UDP length
    unsigned short udp_sum;         // Checksum
};

void Listener() {
    pcap_if_t *alldevs; // Devices
    char *dev_name; // Default device
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[LIS][ERR(001)] Not found interface: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    if (alldevs == NULL) {
        fprintf(stderr, "[LIS][ERR(002)] Not found interface\n");
        exit(EXIT_FAILURE);
    }
    
    dev_name = alldevs->name; // Top device assignment
    printf("[LIS] Listening interface: %s\n", dev_name);
    
    pcap_t *handle = pcap_open_live(
        dev_name,                   // Top device
        BUFSIZ,                     // Max package size
        1,                          // Promiscuous mode
        1000,                       // Timeout (ms)
        errbuf
    );
    
    if (handle == NULL) {
        fprintf(stderr, "[LIS][ERR(003)] Not opened interface: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }
    
    printf("[LIS] Interface opened!\n");
    
    pcap_loop(handle, -1, Handler, NULL);
    
    pcap_close(handle);
    pcap_freealldevs(alldevs);
}

void Handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    
    // Only IPv4
    if (ntohs(eth->ether_type) == 0x0800) {
        /* | Ethernet Header (14 byte) | IP Header | TCP/UDP Header | Data | */
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        
        printf("[LIS/HAND] Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("[LIS/HAND] Target IP: %s\n", inet_ntoa(ip->iph_destip));
        printf("[LIS/HAND] Protocol: %d\n", ip->iph_protocol);
        printf("[LIS/HAND] Packet size: %d bytes\n", header->len);
        
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
            printf("[LIS/HAND] TCP Source Port: %d\n", ntohs(tcp->tcp_sport));
            printf("[LIS/HAND] TCP Target Port: %d\n", ntohs(tcp->tcp_dport));
            printf("[LIS/HAND] TCP Flags: 0x%02x\n", tcp->tcp_flags);
            
            // SYN flood detection
            if (tcp->tcp_flags & 0x02) { // SYN flag
                printf("[LIS/HAND] SYN packet detected\n");
            }
        }
        else if (ip->iph_protocol == IPPROTO_UDP) {
            struct udpheader *udp = (struct udpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
            printf("[LIS/HAND] UDP Source Port: %d\n", ntohs(udp->udp_sport));
            printf("[LIS/HAND] UDP Target Port: %d\n", ntohs(udp->udp_dport));
            printf("[LIS/HAND] UDP Length: %d\n", ntohs(udp->udp_len));
        }
        else if (ip->iph_protocol == IPPROTO_ICMP) {
            printf("[LIS/HAND] ICMP packet detected\n");
        }
    }
}