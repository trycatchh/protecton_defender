#ifndef TYPES_H
#define TYPES_H

#include <pcap.h>

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


#endif // TYPES_H