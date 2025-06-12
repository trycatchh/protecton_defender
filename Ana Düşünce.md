<a href="https://github.com/trycatchh/protecton_defender/blob/documents/English/Main%20Throught.md">🇺🇸 For English</a>

### [Ağ Trafiğini Dinleme](https://github.com/trycatchh/protecton_defender/blob/documents/A%C4%9F%20Trafi%C4%9Fini%20Dinleme.md)
- Ağ arayüzünden (eth0 gibi) gelen tüm paketleri dinler.
- Kaynak IP adreslerini ve paket sayılarını takip eder.

### [Anormal Trafik Tespiti](https://github.com/trycatchh/protecton_defender/blob/documents/Anormal%20Trafik%20Tespiti.md)
- Her IP için belirli zaman aralığında (örnek: 10 saniye) gelen paket sayısını sayar.
- Önceden belirlendiği eşik değerini (örnek: 100 paket) aşan IP'leri potansiyel saldırgan olarak işaretler.

### Engelleme Mekanizması
- Şüpheli IP'leri engellemek için iptables (Linux Firewall; Windows için farklı çözümler kullanılır) kullanır.
- Engelleme süresi için zaman aşımı koyar.

## Ana Bileşenler ve İşleyiş
- Libpcap kütüphanesi kullanılır.
- Ağ kartını promiscuous (özel alım) modda dinler.
- Gelen her paketin:
  - Kaynak IP adresini alır.
  - Paket boyutunu ve zamanını kaydeder.

### IP Takip Sistemi
- IP için örnek veri yapısı:
```c
typedef struct {
  char ip;       // IPv4 adresi için.
  int packet_count;  // Belirli zaman aralığındaki paket sayısı.
  time_t last_seen;  // Son görülme zamanı.
} IpTracker;
```
- Her yeni IP için bu yapıdan bir örnek oluşturulur.
- Mevcut IP'lerin sayaçları güncellenir.

### Saldırı Tespit Algoritması
- Paket yakala.
- Kaynak IP paket listesinde var mı?
  - [EVET] Sayaç arttırılır.
    - Sayaç > Eşik değer mi?
      - [EVET] IP'yi engelle (iptables/firewall).
        - Sayaç sıfırlanır.
      - [HAYIR] Devam et.
  - [HAYIR] Yeni IP eklenir.

### Örnek Engelleme Mekanizması
- Sistem çağrısı (system call) ile iptables çağrılır:
```c
void block_ip(const char *ip) {
  char command;
  snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP", ip); // Komut hazırlanıyor.
  system(command); // Sistem tarafında komut çalıştırılıyor.
  // Log eklenebilir...
}
```
*Not: system() fonksiyonunun güvenlik riskleri olabilir, dikkatli kullanılır.*

### Zaman Yönetimi
- Periyodik olarak (örnek: her 10 saniyede bir) sayaçlar sıfırlanır.
- Bunun için ayrı bir thread kullanılır:
```c
void *reset_counters(void *arg) { // Thread fonksiyonu
  while(1) {
    sleep(TIME_WINDOW); // 10 saniye bekle.
    // Sayaç sıfırlama fonksiyonu çağrılır.
  }
}
```

## Çözümler
1. Performans
   - Çok sayıda IP ile başa çıkmak için hash tablosu kullanılır.
   - Bellek yönetimi ve optimizasyon yapılır.
2. Paket Çeşitleri
   - Sadece belirli paket türleri sayılır (örneğin SYN flood).
   - Paket boyutlarına dikkat edilir.
3. Kullanıcı Taraflı
   - Sayılması gereken paketler kullanıcı tarafından belirlenebilir.
   - Engellenen paketlerin analizi sıkıştırılmış formatta loglanır.

### Güvenlik Önlemleri
- Root yetkisi gerektirir.
- iptables kuralları temizlenir.
- Saldırı tespiti alarmı oluşturulur.

## Sonraki Adımlar
- Gelişmiş Algoritmalar:
  - Machine learning tabanlı anomali tespiti.
  - Paket içeriği analizi.
- Dağıtık Sistem:
  - Birden çok sunucu arasında IP bilgisi paylaşımı.
  - Merkezi yönetim paneli.
- Protokol Bazlı Savunma:
  - HTTP flood koruması.
  - DNS amplifikasyon saldırılarına karşı önlem.


<br>Saygılarla, @p0unter
