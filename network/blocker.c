#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "../include/network/detector.h"

#define BLOCK_DURATION 300 // 5 Minutes
#define TABLE_SIZE 10000
#define MAX_BLOCKED_IPS 1000
#define THRESHOLD 100

// Fixed whitelist definition
const char* whitelist[] = {"192.168.1.1", "10.0.0.1", "127.0.0.1"};
const int whitelist_count = 3;

typedef struct {
    char ip[16];
    time_t block_time;
} BlockEntry;

typedef struct {
    char ip[16];
    time_t block_time;
} BlockedIP;

// Global variables
BlockedIP blocked_ips[MAX_BLOCKED_IPS];
int blocked_count = 0;
BlockEntry* blocked_table[TABLE_SIZE];

// Netfilter handles (declare as extern if defined elsewhere)
struct nfq_handle *h = NULL;
struct nfq_q_handle *qh = NULL;

// Statistics variables (declare as extern if defined in detector.c)
extern int packet_count;
extern double syn_ack_ratio;
extern double entropy_change;

// Function declarations
int should_block_packet(const char *src_ip);
void add_to_blocked(const char *ip);

void block_ip_iptables(const char *ip) {
    char command[256];
    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);
    printf("[BLK/B] %s address blocked.\n", ip);
}

void block_ip_ipset(const char *ip) {
    char command[256];
    snprintf(command, sizeof(command), "ipset add blacklist %s 2>/dev/null", ip);
    system(command);
}

void unblock_ip_ipset(const char *ip) {
    char command[256];
    snprintf(command, sizeof(command), "ipset del blacklist %s 2>/dev/null", ip);
    system(command);
}

void unblock_ip_iptables(const char *ip) {
    char command[256];
    snprintf(command, sizeof(command), "iptables -D INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);
    printf("[BLK/UB] %s address unblocked.\n", ip);
}

static u_int32_t block_packet(struct nfq_q_handle *qh, uint32_t id) {
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

// Fixed process_packets function
void process_packets(int fd) {
    char buf[4096];
    int rv = recv(fd, buf, sizeof(buf), 0);
    
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t id;
    struct nfq_data *nfa = NULL;  // Initialize to NULL

    if (rv >= 0) {
        nfq_handle_packet(h, buf, rv);
        
        if (nfa) {  // Check if nfa is valid
            ph = nfq_get_msg_packet_hdr(nfa);
            if (ph) {
                id = ntohl(ph->packet_id);
                
                char src_ip[INET_ADDRSTRLEN];
                // IP extraction would go here
                
                if (should_block_packet(src_ip)) { 
                    block_packet(qh, id);
                } else {
                    nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }
            }
        }
    }
}

void check_block_timeouts() {
    time_t current = time(NULL);

    for (int i = 0; i < blocked_count; i++) {
        if (difftime(current, blocked_ips[i].block_time) > BLOCK_DURATION) {
            unblock_ip_iptables(blocked_ips[i].ip);

            // Remove from blocked ips list
            for (int j = i; j < blocked_count - 1; j++) {
                blocked_ips[j] = blocked_ips[j+1];
            }
            blocked_count--;
            i--;    
        }
    }
}

// Thread for periodic control
void* block_monitor_thread(void *arg) {
    (void)arg;  // Mark parameter as unused
    while(1) {
        sleep(60);
        check_block_timeouts();
    }
    return NULL;
}

void apply_rate_limit_iptables(const char *ip, const int limit) {
    char command[512];
    snprintf(command, sizeof(command),
    "iptables -A INPUT -s %s -m limit --limit %d/sec -j ACCEPT; "
    "iptables -A INPUT -s %s -j DROP", ip, limit, ip);
    system(command);
}

void block_udp_flood_iptables(const char *ip) {
    char command[256];
    snprintf(command, sizeof(command), "iptables -A INPUT -s %s -p udp -j DROP", ip);
    system(command);
}

unsigned int hash_ip(const char *ip) {
    unsigned int hash = 0;
    for (int i = 0; ip[i]; i++) {
        hash = (hash * 31) + ip[i];
    }
    return hash % TABLE_SIZE;
}

void add_to_blocked(const char *ip) {
    if (blocked_count >= MAX_BLOCKED_IPS) {
        printf("[BLK/ERR] Maximum blocked IP limit reached.\n");
        return;
    }
    
    // Check if already blocked
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i].ip, ip) == 0) {
            return; // Already in list
        }
    }
    
    // Add new IP
    strncpy(blocked_ips[blocked_count].ip, ip, sizeof(blocked_ips[blocked_count].ip) - 1);
    blocked_ips[blocked_count].ip[sizeof(blocked_ips[blocked_count].ip) - 1] = '\0';
    blocked_ips[blocked_count].block_time = time(NULL);
    blocked_count++;
    
    printf("[BLK/ADD] Added %s to blocked list. Total blocked: %d\n", ip, blocked_count);
}

int is_whitelisted(const char *ip) {
    for (int i = 0; i < whitelist_count; i++) {
        if (strcmp(ip, whitelist[i]) == 0) return 1;
    }
    return 0;
}

int confirm_attack(const char *ip) {
    // Get current statistics from detector
    float current_syn_ack_ratio = get_syn_ack_ratio(ip);
    
    // Simple attack confirmation logic
    if (current_syn_ack_ratio > 3.0) {
        printf("[BLK/ATTACK] Attack confirmed from %s (SYN/ACK ratio: %.2f)\n", ip, current_syn_ack_ratio);
        return 1;
    }
    return 0;
}

int should_block_packet(const char *src_ip) {
    // Check whitelist first
    if (is_whitelisted(src_ip)) {
        return 0;
    }
    
    // Check if already blocked
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i].ip, src_ip) == 0) {
            return 1;
        }
    }
    
    // Check for attack patterns
    if (confirm_attack(src_ip)) {
        add_to_blocked(src_ip);
        block_ip_iptables(src_ip);
        return 1;
    }
    
    return 0;
}

// Auto-blocking function to be called from detector
void auto_block_ip(const char *ip) {
    if (!is_whitelisted(ip)) {
        add_to_blocked(ip);
        block_ip_iptables(ip);
        block_ip_ipset(ip);
        printf("[BLK/AUTO] Auto-blocked suspicious IP: %s\n", ip);
    }
}

// Initialize blocking system
int init_blocker() {
    pthread_t monitor_thread;
    
    // Start monitoring thread
    if (pthread_create(&monitor_thread, NULL, block_monitor_thread, NULL) != 0) {
        fprintf(stderr, "[BLK/ERR] Failed to create monitor thread\n");
        return -1;
    }
    
    // Detach thread so it runs independently
    pthread_detach(monitor_thread);
    
    printf("[BLK/INIT] Blocker system initialized successfully\n");
    return 0;
}