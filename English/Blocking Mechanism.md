<a href="https://github.com/trycatchh/protecton_defender/blob/documents/Engelleme%20Mekanizmas%C4%B1.md">🇹🇷 For Turkish</a>

### 1. Firewall-Based Blocking (Most Common)
- **iptables (Linux)**: Direct kernel-level packet filtering
- **Windows Firewall**: COM API or command line integration
- **PF (BSD)**: Packet Filter technology

### 2. Network-Level Blocking
- ISP-level blocking with BGP FlowSpec
- Router ACLs (Access Control Lists) usage

### 3. Application-Level Blocking
- Reverse proxy usage (Nginx, HAProxy)
- Web Application Firewall (WAF) integration

## Practical Implementation in C

### 1. iptables Integration (Simplest Method)

```c
#include <stdlib.h>
#include <stdio.h>

void block_ip_iptables(const char *ip) {
    char command[256];
    
    // Add iptables rule
    snprintf(command, sizeof(command), 
             "iptables -A INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);
    
    // Logging
    printf("[BLOCKED] %s address blocked\n", ip);
}

void unblock_ip_iptables(const char *ip) {
    char command[256];
    
    // Remove iptables rule
    snprintf(command, sizeof(command), 
             "iptables -D INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);
    
    // Logging
    printf("[UNBLOCKED] %s unblocked\n", ip);
}
```

### 2. Local Blocking with Netfilter Queue (More Advanced)

```c
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static u_int32_t block_packet(struct nfq_q_handle *qh, uint32_t id) {
    // Drop packet (DROP)
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

void process_packets(int fd) {
    char buf[4096];
    int rv = recv(fd, buf, sizeof(buf), 0);
    
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t id;
    
    if (rv >= 0) {
        nfq_handle_packet(h, buf, rv); // h: netfilter handle
        nfq_get_payload(buf, &ph);
        id = ntohl(ph->packet_id);
        
        if (should_block_packet(buf)) { // Your custom detection function
            block_packet(qh, id);
        } else {
            nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }
    }
}
```

### 3. Automatic Unblocking with Timeout

```c
#include <time.h>

#define BLOCK_DURATION 300 // 5 minutes

typedef struct {
    char ip[16];
    time_t block_time;
} BlockedIP;

BlockedIP blocked_ips[1000];
int blocked_count = 0;

void check_block_timeouts() {
    time_t current = time(NULL);
    
    for (int i = 0; i < blocked_count; i++) {
        if (difftime(current, blocked_ips[i].block_time) > BLOCK_DURATION) {
            unblock_ip_iptables(blocked_ips[i].ip);
            
            // Remove from blocked list
            for (int j = i; j < blocked_count - 1; j++) {
                blocked_ips[j] = blocked_ips[j+1];
            }
            blocked_count--;
            i--;
        }
    }
}

// Thread for periodic checking
void* block_monitor_thread(void *arg) {
    while(1) {
        sleep(60); // Check every 60 seconds
        check_block_timeouts();
    }
    return NULL;
}
```

## Blocking Strategies

### 1. Simple IP Blocking
- Complete traffic blocking
- Advantage: Simple implementation
- Disadvantage: Service disruption with false positives

### 2. Rate Limiting
- Traffic shaping above a certain limit
```c
void apply_rate_limit(const char *ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "iptables -A INPUT -s %s -m limit --limit 50/sec -j ACCEPT; "
        "iptables -A INPUT -s %s -j DROP", ip, ip);
    system(cmd);
}
```

### 3. Protocol-Based Blocking
- Blocking only specific protocols
```c
void block_udp_flood(const char *ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "iptables -A INPUT -s %s -p udp -j DROP", ip);
    system(cmd);
}
```

## Performance Optimization

### 1. IP Set Usage
```c
void block_ip_ipset(const char *ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ipset add blacklist %s", ip);
    system(cmd);
}

// Pre-created ipset rule:
// iptables -A INPUT -m set --match-set blacklist src -j DROP
```

### 2. Hash Table for Fast Access
```c
#define TABLE_SIZE 10000

typedef struct {
    char ip[16];
    time_t block_time;
} BlockEntry;

BlockEntry* blocked_table[TABLE_SIZE];

unsigned int hash_ip(const char *ip) {
    unsigned int hash = 0;
    for (int i = 0; ip[i]; i++) {
        hash = (hash * 31) + ip[i];
    }
    return hash % TABLE_SIZE;
}

void add_to_blocked(const char *ip) {
    unsigned int index = hash_ip(ip);
    // Use linked list for collision resolution
}
```

## Security Measures

### 1. Whitelist Implementation
```c
const char *whitelist[] = {"192.168.1.1", "10.0.0.1"};

int is_whitelisted(const char *ip) {
    for (int i = 0; i < sizeof(whitelist)/sizeof(whitelist[0]); i++) {
        if (strcmp(ip, whitelist[i]) == 0) return 1;
    }
    return 0;
}
```

### 2. Multi-Verification
```c
int confirm_attack(const char *ip) {
    // Validate attack with multiple metrics
    if (packet_count > THRESHOLD && 
        syn_ack_ratio > 3.0 && 
        entropy_change > 0.5) {
        return 1;
    }
    return 0;
}
```

## Challenges and Solutions

1. **IP Spoofing**:
   - TCP Protocol: SYN flood protection
   - UDP/ICMP: Difficult to verify real source IP

2. **Distributed Attacks (DDoS)**:
   - IP geographic distribution analysis
   - ASN (Autonomous System Number) based blocking

3. **Dynamic IPs**:
   - Keep blocking duration short
   - CIDR block blocking (use carefully)

## Best Practices

1. **Gradual Blocking**:
   - Warning → Rate Limiting → Full Blocking

2. **Automatic Recovery**:
   ```c
   void auto_unblock() {
       // Automatic unblocking under low system load
       if (system_load < 0.3) {
           reduce_block_levels();
       }
   }
   ```

3. **Detailed Logging**:
   - Blocked IP
   - Blocking reason (which metric)
   - Block duration
   - Traffic statistics

## Next Steps

1. **Cloud Integration**:
   - AWS WAF, Cloudflare API integration
   - Global blocking distribution

2. **Behavior Analysis**:
   - Captcha redirection
   - JavaScript Challenge

3. **Machine Learning**:
   - Automatic policy generation with anomaly detection models
   - Attack pattern recognition
  
<br>Best regards, @p0unter
