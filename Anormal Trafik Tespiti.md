<a href="https://github.com/trycatchh/protecton_defender/blob/documents/English/Abnormal%20Traffic%20Detection.md">🇺🇸 For English</a>

### 1. İstatistiksel Temelli Yöntemler
- **Eşik Değer Sistemi (Thresholding)**
  - Belirli zaman aralığında IP başına paket sayısı
  - Paket boyutu dağılımı anomalileri
  - Protokol dağılımındaki dengesizlikler
### 2. Davranışsal Analiz
- **IP Profili Oluşturma**
  - Coğrafi lokasyon
  - Kullanılan portlar
  - Protokol tercihleri
- **Oturum Davranışı**
  - Bağlantı süresi anomalileri
  - Paket zamanlamasındaki düzensizlikler

### 3. Makine Öğrenimi Yaklaşımları
- **Anomali Tespit Algoritmaları**
  - Isolation Forests
  - One-Class SVM
  - Autoencoders
- **Özellik Mühendisliği**
  - Paket/saniye oranı
  - SYN/ACK oranı
  - Kaynak IP çeşitliliği

### Temel Rate Limiting Sistemi
```c
#include <time.h>

#define TIME_WINDOW 10  // 10 saniyelik analiz penceresi
#define THRESHOLD 100   // Maksimum izin verilen paket sayısı

typedef struct {
    char ip[16];
    int packet_count;
    time_t first_seen;
} IpTracker;

void detect_anomaly(IpTracker *ip_list, const char *current_ip) {
    time_t current_time = time(NULL);
    
    for(int i = 0; i < MAX_IPS; i++) {
        if(strcmp(ip_list[i].ip, current_ip) == 0) {
            // Süre aşımı kontrolü
            if(difftime(current_time, ip_list[i].first_seen) > TIME_WINDOW) {
                ip_list[i].packet_count = 0;
                ip_list[i].first_seen = current_time;
            }
            
            // Paket sayısını artır
            ip_list[i].packet_count++;
            
            // Anomali kontrolü
            if(ip_list[i].packet_count > THRESHOLD) {
                block_ip(current_ip);
                printf("[!] Anomali Tespit Edildi: %s\n", current_ip);
            }
            break;
        }
    }
}
```

### Gelişmiş SYN Flood Tespiti
```c
void analyze_tcp_packet(const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + sizeof(struct ethheader));
    struct tcphdr *tcp_header = (struct tcphdr*)(packet + sizeof(struct ethheader) + sizeof(struct ip));
    
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    
    // SYN paketi kontrolü
    if(tcp_header->syn && !tcp_header->ack) {
        increment_syn_counter(src_ip);
    }
    
    // ACK paketi kontrolü
    if(tcp_header->ack) {
        increment_ack_counter(src_ip);
    }
    
    // SYN/ACK oranı anomalisi
    float ratio = get_syn_ack_ratio(src_ip);
    if(ratio > 3.0) {  // Normalde ~1 olması beklenir
        printf("[!] SYN Flood Şüphesi: %s (Oran: %.2f)\n", src_ip, ratio);
    }
}
```

## Anomali Tespitinde Kullanılan Metrikler

| Metrik | Normal Değer | Anormal Değer | Açıklama |
|--------|--------------|---------------|----------|
| Paket/Saniye | < 50 | > 500 | IP başına paket hızı |
| SYN/ACK Oranı | ≈1 | >3 | Tamamlanmamış bağlantılar |
| UDP/TCP Oranı | Değişken | >10 | UDP flood işareti |
| Kaynak IP Çeşitliliği | Düşük | Yüksek | Dağıtık saldırı işareti |
| Paket Boyutu Varyansı | Düşük | Yüksek | Farklı saldırı teknikleri |

## Optimizasyon Teknikleri

1. **Verimli Veri Yapıları**
   - Hash tabloları ile O(1) erişim
   - Bloom filtreleri ile hafıza optimizasyonu

2. **Periyodik Analiz**
   ```c
   void *periodic_analysis(void *arg) {
       while(1) {
           sleep(ANALYSIS_INTERVAL);
           calculate_traffic_stats();
           detect_long_term_anomalies();
           clean_old_entries();
       }
   }
   ```

3. **Entropi Tabanlı Tespit**
   ```c
   float calculate_ip_entropy() {
       // Kaynak IP'lerin entropisini hesapla
       // Ani entropi değişimi saldırı işareti olabilir
   }
   ```

## Zorluklar ve Çözümler

1. **Yanlış Pozitifler**
   - Beyaz liste uygulama
   - Dinamik eşik ayarlama
   - Öğrenme modu (learning mode) implementasyonu

2. **Performans Sorunları**
   - Çoklu iş parçacığı (multithreading)
   - DPDK (Data Plane Development Kit) entegrasyonu
   - Hızlı arama algoritmaları

3. **Gizli Saldırılar**
   - Derin paket incelemesi (DPI)
   - Davranışsal imza analizi
   - Makine öğrenimi modelleri

## Sonraki Adımlar

1. **Tarihsel Veri Analizi**
   - Hareketli ortalama hesaplama
   - Zaman serisi analizi

2. **Protokol Spesifik Tespit**
   - HTTP flood koruması
   - DNS amplification tespiti

3. **Dağıtık Sistem Entegrasyonu**
   - Birden çok node arasında bilgi paylaşımı
   - Merkezi analiz sunucusu

<br>Saygılarla, @p0unter
