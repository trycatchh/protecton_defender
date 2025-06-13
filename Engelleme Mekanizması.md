<a href="https://github.com/trycatchh/protecton_defender/blob/documents/English/Blocking%20Mechanism.md">🇺🇸 For English</a>

### 1. Firewall Temelli Engelleme (En Yaygın)
- **iptables (Linux)**: Doğrudan kernel seviyesinde paket filtreleme
- **Windows Firewall**: COM API veya komut satırı entegrasyonu
- **PF (BSD)**: Packet Filter teknolojisi

### 2. Ağ Seviyesinde Engelleme
- BGP FlowSpec ile ISP seviyesinde engelleme
- Router ACL'leri (Access Control Lists) kullanımı

### 3. Uygulama Seviyesinde Engelleme
- Reverse proxy kullanımı (Nginx, HAProxy)
- Web Uygulama Güvenlik Duvarı (WAF) entegrasyonu

## C'de Pratik Uygulama

### 1. iptables Entegrasyonu (En Basit Yöntem)

```c
#include <stdlib.h>
#include <stdio.h>

void block_ip_iptables(const char *ip) {
    char command[256];
    
    // iptables kuralı ekle
    snprintf(command, sizeof(command), 
             "iptables -A INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);
    
    // Loglama
    printf("[ENGEL] %s adresi engellendi\n", ip);
}

void unblock_ip_iptables(const char *ip) {
    char command[256];
    
    // iptables kuralını kaldır
    snprintf(command, sizeof(command), 
             "iptables -D INPUT -s %s -j DROP 2>/dev/null", ip);
    system(command);
    
    // Loglama
    printf("[KALDIR] %s engeli kaldırıldı\n", ip);
}
```

### 2. Netfilter Queue ile Yerel Engelleme (Daha Gelişmiş)

```c
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

static u_int32_t block_packet(struct nfq_q_handle *qh, uint32_t id) {
    // Paketi düşür (DROP)
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
        
        if (should_block_packet(buf)) { // Kendi tespit fonksiyonunuz
            block_packet(qh, id);
        } else {
            nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }
    }
}
```

### 3. Zaman Aşımı ile Otomatik Engelleme Kaldırma

```c
#include <time.h>

#define BLOCK_DURATION 300 // 5 dakika

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
            
            // Engellenenler listesinden kaldır
            for (int j = i; j < blocked_count - 1; j++) {
                blocked_ips[j] = blocked_ips[j+1];
            }
            blocked_count--;
            i--;
        }
    }
}

// Periyodik kontrol için thread
void* block_monitor_thread(void *arg) {
    while(1) {
        sleep(60); // Her 60 saniyede bir kontrol
        check_block_timeouts();
    }
    return NULL;
}
```

## Engelleme Stratejileri

### 1. Basit IP Engelleme
- Tüm trafiği tamamen engelleme
- Avantaj: Basit uygulama
- Dezavantaj: Yanlış pozitiflerde hizmet kesintisi

### 2. Rate Limiting
- Belirli bir limitin üzerinde trafiği şekillendirme
```c
void apply_rate_limit(const char *ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "iptables -A INPUT -s %s -m limit --limit 50/sec -j ACCEPT; "
        "iptables -A INPUT -s %s -j DROP", ip, ip);
    system(cmd);
}
```

### 3. Protokol Bazlı Engelleme
- Sadece belirli protokolleri engelleme
```c
void block_udp_flood(const char *ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "iptables -A INPUT -s %s -p udp -j DROP", ip);
    system(cmd);
}
```

## Performans Optimizasyonu

### 1. IP Set Kullanımı
```c
void block_ip_ipset(const char *ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ipset add blacklist %s", ip);
    system(cmd);
}

// Önceden oluşturulmuş ipset kuralı:
// iptables -A INPUT -m set --match-set blacklist src -j DROP
```

### 2. Hash Tablolu Hızlı Erişim
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
    // Çakışma çözümü için bağlı liste kullan
}
```

## Güvenlik Önlemleri

### 1. Beyaz Liste Uygulaması
```c
const char *whitelist[] = {"192.168.1.1", "10.0.0.1"};

int is_whitelisted(const char *ip) {
    for (int i = 0; i < sizeof(whitelist)/sizeof(whitelist[0]); i++) {
        if (strcmp(ip, whitelist[i]) == 0) return 1;
    }
    return 0;
}
```

### 2. Çoklu Doğrulama
```c
int confirm_attack(const char *ip) {
    // Birden fazla metrikle saldırıyı doğrula
    if (packet_count > THRESHOLD && 
        syn_ack_ratio > 3.0 && 
        entropy_change > 0.5) {
        return 1;
    }
    return 0;
}
```

## Zorluklar ve Çözümler

1. **IP Spoofing**:
   - TCP Protokolü: SYN flood koruması
   - UDP/ICMP: Gerçek kaynak IP doğrulama zor

2. **Dağıtık Saldırılar (DDoS)**:
   - IP Coğrafi dağılım analizi
   - ASN (Autonomous System Number) bazlı engelleme

3. **Dinamik IP'ler**:
   - Engelleme süresini kısa tutma
   - CIDR blok engelleme (dikkatli kullanım)

## Best Practices

1. **Kademeli Engelleme**:
   - Uyarı → Rate Limiting → Tam Engelleme

2. **Otomatik İyileştirme**:
   ```c
   void auto_unblock() {
       // Düşük sistem yükünde otomatik engel kaldırma
       if (system_load < 0.3) {
           reduce_block_levels();
       }
   }
   ```

3. **Detaylı Loglama**:
   - Engellenen IP
   - Engelleme nedeni (hangi metrik)
   - Engelleme süresi
   - Trafik istatistikleri

## Sonraki Adımlar

1. **Bulut Entegrasyonu**:
   - AWS WAF, Cloudflare API entegrasyonu
   - Global engelleme dağıtımı

2. **Davranış Analizi**:
   - Captcha yönlendirme
   - JavaScript Challenge

3. **Makine Öğrenimi**:
   - Anomali tespit modeli ile otomatik politika oluşturma
   - Saldırı örüntü tanıma
  
<br>Saygılarımla, @p0unter
