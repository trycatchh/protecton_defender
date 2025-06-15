#include "../include/network/listener.h"
#include "../include/network/detector.h"
#include "../include/network/blocker.h"
#include "definitions/headers.h"

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

void listener_interface() {
    pcap_if_t *alldevs; // Devices
    char *dev_name; // Default device
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[LIS/L][ERR(001)] Not found interface: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    if (alldevs == NULL) {
        fprintf(stderr, "[LIS/L][ERR(002)] Not found interface\n");
        exit(EXIT_FAILURE);
    }
    
    dev_name = alldevs->name; // Top device assignment
    printf("[LIS/L] Listening interface: %s\n", dev_name);
    
    pcap_t *handle = pcap_open_live(
        dev_name,                   // Top device
        BUFSIZ,                     // Max package size
        1,                          // Promiscuous mode
        1000,                       // Timeout (ms)
        errbuf
    );
    
    if (handle == NULL) {
        fprintf(stderr, "[LIS/L][ERR(003)] Not opened interface: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }
    
    printf("[LIS/L] Interface opened!\n");
    
    pcap_loop(handle, -1, packet_handler, NULL);
    
    pcap_close(handle);
    pcap_freealldevs(alldevs);
}

void packet_handler(unsigned char *args __attribute__((unused)), const struct pcap_pkthdr *header, const unsigned char *packet) {
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
            
            // Call TCP analyzer
            anlyze_tcp(packet);
        }
        else if (ip->iph_protocol == IPPROTO_UDP) {
            struct udpheader *udp = (struct udpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
            printf("[LIS/HAND] UDP Source Port: %d\n", ntohs(udp->udp_sport));
            printf("[LIS/HAND] UDP Target Port: %d\n", ntohs(udp->udp_dport));
            printf("[LIS/HAND] UDP Length: %d\n", ntohs(udp->udp_len));
            
            // General anomaly detection for UDP
            char src_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip->iph_sourceip), src_ip, INET_ADDRSTRLEN);
            detect_anomaly(src_ip);
        }
        else if (ip->iph_protocol == IPPROTO_ICMP) {
            printf("[LIS/HAND] ICMP packet detected\n");
            
            // General anomaly detection for ICMP
            char src_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip->iph_sourceip), src_ip, INET_ADDRSTRLEN);
            detect_anomaly(src_ip);
        }
    }
}

void enhanced_packet_handler(unsigned char *args __attribute__((unused)), 
                           const struct pcap_pkthdr *header, 
                           const unsigned char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    
    // Only IPv4
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->iph_sourceip), src_ip, INET_ADDRSTRLEN);
        
        // Check if IP is already blocked
        if (should_block_packet(src_ip)) {
            printf("[LIS/BLOCKED] Packet from blocked IP %s dropped\n", src_ip);
            return; // Don't process further
        }
        
        printf("[LIS/HAND] Source IP: %s\n", src_ip);
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
            
            // Call enhanced TCP analyzer
            enhanced_anlyze_tcp(packet);
        }
        else if (ip->iph_protocol == IPPROTO_UDP) {
            struct udpheader *udp = (struct udpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
            printf("[LIS/HAND] UDP Source Port: %d\n", ntohs(udp->udp_sport));
            printf("[LIS/HAND] UDP Target Port: %d\n", ntohs(udp->udp_dport));
            printf("[LIS/HAND] UDP Length: %d\n", ntohs(udp->udp_len));
            
            // Enhanced anomaly detection for UDP
            enhanced_detect_anomaly(src_ip);
        }
        else if (ip->iph_protocol == IPPROTO_ICMP) {
            printf("[LIS/HAND] ICMP packet detected\n");
            
            // Enhanced anomaly detection for ICMP
            enhanced_detect_anomaly(src_ip);
        }
    }
}

void enhanced_listener_interface() {
    pcap_if_t *alldevs;
    char *dev_name;
    
    // Initialize blocker system first
    if (init_blocker() != 0) {
        fprintf(stderr, "[LIS/ERR] Failed to initialize blocker system\n");
        exit(EXIT_FAILURE);
    }
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[LIS/L][ERR(001)] Not found interface: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    if (alldevs == NULL) {
        fprintf(stderr, "[LIS/L][ERR(002)] Not found interface\n");
        exit(EXIT_FAILURE);
    }
    
    dev_name = alldevs->name;
    printf("[LIS/L] Listening interface: %s\n", dev_name);
    
    pcap_t *handle = pcap_open_live(
        dev_name,
        BUFSIZ,
        1,
        1000,
        errbuf
    );
    
    if (handle == NULL) {
        fprintf(stderr, "[LIS/L][ERR(003)] Not opened interface: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }
    
    printf("[LIS/L] Interface opened with integrated blocking!\n");
    
    // Use enhanced packet handler
    pcap_loop(handle, -1, enhanced_packet_handler, NULL);
    
    pcap_close(handle);
    pcap_freealldevs(alldevs);
}