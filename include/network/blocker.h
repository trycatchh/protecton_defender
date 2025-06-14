#ifndef BLOCKER_H
#define BLOCKER_H

#include <stdint.h>

void block_ip_iptables(const char *ip);
void block_ip_ipset(const char *ip);
void unblock_ip_ipset(const char *ip);
void unblock_ip_iptables(const char *ip);
static u_int32_t block_packet(struct nfq_q_handle *qh, uint32_t id);
void process_packets(int fd);
void check_block_timeouts();
void* block_monitor_thread(void *arg);
void apply_rate_limit_iptables(const char *ip, const int limit);
void block_udp_flood_iptables(const char *ip);
unsigned int hash_ip(const char *ip);
void add_to_blocked(const char *ip);
int is_whitelisted(const char *ip);
int confirm_attack(const char *ip);

#endif // BLOCKER_H
