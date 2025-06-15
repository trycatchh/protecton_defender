#ifndef BLOCKER_H
#define BLOCKER_H

#include <stdint.h>

void block_ip_iptables(const char *ip);
void unblock_ip_iptables(const char *ip);
void block_ip_ipset(const char *ip);
void unblock_ip_ipset(const char *ip);
void apply_rate_limit_iptables(const char *ip, const int limit);
void block_udp_flood_iptables(const char *ip);
void auto_block_ip(const char *ip);
int should_block_packet(const char *src_ip);
int is_whitelisted(const char *ip);
int confirm_attack(const char *ip);
int init_blocker(void);
void* block_monitor_thread(void *arg);

#endif // BLOCKER_H
