#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define BLOCK_DURATION 300 // 5 Minutes
#define TABLE_SIZE 10000
#define *WHITELIST= {"192.168.1.1","10.0.0.1"};

typedef struct {
	char ip[16];
	time_t block_time;
} BlockEntry;

typedef struct {
	char ip[16];
	time_t block_time;
} BlockedIP;

BlockedIP blocked_ips[1000];
int blocked_count = 0;

BlockEntry* blocked_table[TABLE_SIZE];

void block_ip_iptables(const char *ip) {

	char command[256];

	snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP 2>/dev/null", ip);
	system(command);

	printf("[BLK/B] %s address blocked.\n", ip);

}

void block_ip_ipset(const char *ip) {

	char command[256];
	
	snprintf(command, sizeof(command), "ipset add blacklist %s", ip);
	system(command);

}

void unblock_ip_ipset(const char *ip) {

	char command[256];
	
	snprintf(command, sizeof(command), "ipset del blacklist %s", ip);
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

void process_packets(int fd) {

	char buf[4096];

	int rv = recv(fd, buf, siezof(buf), 0);

	struct nfqnl_msg_packet_hdr *ph;
	uint32_t id;

	if (rv >= 0) {
		nfq_handle_packet(h, buf, rv);
		nfq_get_payload(buf, &ph);
		id = ntohl(ph->packet_id);

		if (should_block_packet(buf)) { 
			block_packet(qh, id);
		} else {
			nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
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

	while(1) {
		sleep(60);
		check_block_timeouts();
	}

	return NULL;

}

void apply_rate_limit_iptables(const char *ip, const int limit) {

	char command[256];

	snprintf(command, sizeof(command),
	"iptables -A INPUT -s %s -m limit --limit %d/sec -j ACCEPT;"
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
	unsigned int index = hash_ip(ip);
}

int is_whitelisted(const char *ip) {

	for (int i = 0; i < sizeof(whitelist)/sizeof(whitelist[0]); i++) {
		if (strcmp(ip, whitelist[i]) == 0) return 1;
	}
	return 0;
}

int confirm_attack(const char *ip) {

	if (packet_count > THRESHOLD && syn_ack_ratio > 3.0 && entropy_change > 0.5) return 1;

	return 0;

}
