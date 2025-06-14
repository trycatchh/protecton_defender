#include "../include/network/detector.h"
#include "definitions/headers.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define TIME_WINDOW 10
#define THRESHOLD 100
#define MAX_IPS 1000
#define SYN_FLOOD_THRESHOLD 50

typedef struct {
    char ip[16];
    int packet_count;
    time_t first_seen;
} IpTracker;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int syn_count;
    int ack_count;
    time_t first_seen;
} SynFloodTracker;

static IpTracker ip_list[MAX_IPS];
static SynFloodTracker syn_trackers[MAX_IPS];
static int ip_count = 0;
static int syn_tracker_count = 0;

void increment_syn_counter(const char *ip) {
    time_t current_time = time(NULL);
    
    for (int i = 0; i < syn_tracker_count; i++) {
        if (strcmp(syn_trackers[i].ip, ip) == 0) {
            if (difftime(current_time, syn_trackers[i].first_seen) > TIME_WINDOW) {
                syn_trackers[i].syn_count = 0;
                syn_trackers[i].ack_count = 0;
                syn_trackers[i].first_seen = current_time;
            }
            syn_trackers[i].syn_count++;
            return;
        }
    }
    
    if (syn_tracker_count < MAX_IPS) {
        strcpy(syn_trackers[syn_tracker_count].ip, ip);
        syn_trackers[syn_tracker_count].syn_count = 1;
        syn_trackers[syn_tracker_count].ack_count = 0;
        syn_trackers[syn_tracker_count].first_seen = current_time;
        syn_tracker_count++;
    }
}

void increment_ack_counter(const char *ip) {
    for (int i = 0; i < syn_tracker_count; i++) {
        if (strcmp(syn_trackers[i].ip, ip) == 0) {
            syn_trackers[i].ack_count++;
            return;
        }
    }
}

float get_syn_ack_ratio(const char *ip) {
    for (int i = 0; i < syn_tracker_count; i++) {
        if (strcmp(syn_trackers[i].ip, ip) == 0) {
            if (syn_trackers[i].ack_count == 0) {
                return syn_trackers[i].syn_count > 0 ? (float)syn_trackers[i].syn_count : 0.0;
            }
            return (float)syn_trackers[i].syn_count / (float)syn_trackers[i].ack_count;
        }
    }
    return 0.0;
}

void detect_anomaly(const char *current_ip) {
    time_t current_time = time(NULL);
    
    for (int i = 0; i < ip_count; i++) {
        if (strcmp(ip_list[i].ip, current_ip) == 0) {
            if (difftime(current_time, ip_list[i].first_seen) > TIME_WINDOW) {
                ip_list[i].packet_count = 0;
                ip_list[i].first_seen = current_time;
            }
            
            ip_list[i].packet_count++;
            
            if (ip_list[i].packet_count > THRESHOLD) {
                printf("[DETEC/ANOMALY][!] Anomaly was detected: %s (Packets: %d)\n", 
                       current_ip, ip_list[i].packet_count);
            }
            return;
        }
    }
    
    if (ip_count < MAX_IPS) {
        strcpy(ip_list[ip_count].ip, current_ip);
        ip_list[ip_count].packet_count = 1;
        ip_list[ip_count].first_seen = current_time;
        ip_count++;
    }
}

void anlyze_tcp(const unsigned char *packet) {
    struct ipheader *iphdr = (struct ipheader*)(packet + sizeof(struct ethheader));
    struct tcpheader *tcphdr = (struct tcpheader*)(packet + sizeof(struct ethheader) + (iphdr->iph_ihl * 4));
    
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iphdr->iph_sourceip), src_ip, INET_ADDRSTRLEN);
    
    // SYN flag check (0x02)
    if (tcphdr->tcp_flags & 0x02 && !(tcphdr->tcp_flags & 0x10)) { // SYN but not ACK
        increment_syn_counter(src_ip);
        printf("[DETEC/TCP] SYN packet from %s:%d to port %d\n", 
               src_ip, ntohs(tcphdr->tcp_sport), ntohs(tcphdr->tcp_dport));
    }
    
    // ACK flag check (0x10)
    if (tcphdr->tcp_flags & 0x10) { // ACK flag
        increment_ack_counter(src_ip);
    }
    
    // RST flag check (0x04) - potential port scan
    if (tcphdr->tcp_flags & 0x04) { // RST flag
        printf("[DETEC/TCP] RST packet from %s - possible port scan\n", src_ip);
    }
    
    // FIN flag check (0x01) - connection termination
    if (tcphdr->tcp_flags & 0x01) { // FIN flag
        printf("[DETEC/TCP] FIN packet from %s\n", src_ip);
    }
    
    // Check SYN/ACK ratio for flood detection
    float ratio = get_syn_ack_ratio(src_ip);
    if (ratio > 3.0) {
        printf("[DETEC/TCP][!] Potential SYN Flood detected from %s (Ratio: %.2f)\n", src_ip, ratio);
    }
    
    // Check for excessive SYN packets
    for (int i = 0; i < syn_tracker_count; i++) {
        if (strcmp(syn_trackers[i].ip, src_ip) == 0) {
            if (syn_trackers[i].syn_count > SYN_FLOOD_THRESHOLD) {
                printf("[DETEC/TCP][!] High SYN count from %s: %d packets\n", 
                       src_ip, syn_trackers[i].syn_count);
            }
            break;
        }
    }
    
    // General packet anomaly detection
    detect_anomaly(src_ip);
}