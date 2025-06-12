<a href="https://github.com/trycatchh/protecton_defender/blob/documents/English/Listenin%20Network%20Traffic.md">🇺🇸 For English</a>

### Ağ Trafiğini Dinleme
C dilinde ağ trafiğini dinlemek için gelenellikle Libcap kütüphanesi kullanılır. Bu, ağ paketlerini yakalamak için endüstri standartı yaklaşımıdır.

### Temel Adımlar
1. Libcap
   - **Promiscuous Mod:** Ağ arayüzünün tüm trafiği dinlemesi.
   - **Packet Filtering:** BPF (Berkeley Packet Filter) ile sadece ilgilenen trafiği yakalama.
   - **Callback Mekanizması:** Paket yakalandığında otomatik çağırılan fonksiyon.
2. Temel Çalışma Akışı:
   - Libcap Başar
   - Ağ Arayüzü Seçiler
   - Paket Yakalama Tanıtıcısı Oluşturulur
   - Filtre Ayarları Yapılır
   - Paket Yakalama Döngüsü
   - Paket İşleme Fonksiyonu
3. Detaylı Adımlar
   - Libcap Başlatma
   ```c
   #include <pcap.h>
   char errbuf[PCAP_ERRBUF_SIZE]; // Hata mesajları için...
   ```
   - Ağ Arayüzü Seçimi
   ```c
   // Otomatik olarak varsayılan arayüzü bulma:
   char *device = pcap_lookupdev(errbuf);
   if (!device) {
    fprintf(stderr, "Arayüz bulunamadı: %s\n", errbuf);
     return 1;
   }
   printf("Dinlenen arayüz: %s\n", device); 
   ```
   - Paket Yakalama Tanıtıcısı Oluşturma
   ```c
   pcap *handle = pcap_open_live(
     device, // Ağ arayüzü.
     BUFSIZ, // Maksimum paket boyutu.
     1,      // Promiscuous mod (1 = açık)
     1000,   // Zaman aşımı (ms)
     errbuf  // Hata tamponu.
   );
   ```
   - Filitre Ayarı
   ```c
   strtuct bpf_program fp;
   char filter_exp[] = "tcp"; // Sadece TCP paketleri.
   bpf_u_int32 subnet_mask, ip;

   // Ağ adresi bilgilerini al.
   pcap_lookupnet(device, &ip, &subnet_mask, errbuf);

   // Filitreyi derle
   pcap_compile(handle, &fp, filter_exp, 0, ip);
   pcap_setfiler(handle, &fp);
   ```
   - Paket İşleme Fonksiyonu
   ```c
   void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
     // Paket işleme kodları...
     printf("Yakalanan paket boyutu: %d\n", header->len);
   }
   ```

## Paket Yapısını Ayrıştırma
Paketleri anlamlı hale getirmek için tipik bir Ethernet paketinin yapısı:
```c
struct ethheader {
    u_char  ether_dhost[6]; // Hedef MAC
    u_char  ether_shost[6]; // Kaynak MAC
    u_short ether_type;     // Protokol türü (IPv4: 0x0800)
};

struct ipheader {
    u_char  iph_ihl:4;      // IP başlığının uzunluğu.
    u_char  iph_ver:4;      // IP versiyonu
    u_char  iph_tos;        // Servisin türü.
    u_short iph_len;        // Toplam uzunluk
    u_short iph_ident;      // Doğrulama
    u_short iph_flag:3;     // Fragmentation flags
    u_short iph_offset:13;  // Fragment offset
    u_char  iph_ttl;        // Time to live
    u_char  iph_protocol;   // Protocol (TCP=6, UDP=17)
    u_short iph_chksum;     // Kontrol
    struct in_addr iph_sourceip;  // Kaynak IP
    struct in_addr iph_destip;    // Hedef IP
};

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    
    // Sadece IPv4 paketleri
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        
        printf("Kaynak IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Hedef IP: %s\n", inet_ntoa(ip->iph_destip));
        
        // TCP paketleri
        if (ip->iph_protocol == IPPROTO_TCP) {
            // TCP başlığını ayrıştır
        }
    }
}
```

### Notlar
1. Performans Optimizasyonu
   - Büyük veriler için statik bellek kullanır.
2. Farklı Protokoller
   - TCP: ```struct tcphdr``` (netinet/tcp.h)
   - UDP: ```struct udphdr``` (netinet/udp.h)
   - ICMP: ```struct icmphdr``` (netinet/ip_icmp.h)
3. Hash Tablosu Optimizasyonu
   - Büyük ölçete IP takibi için hash tablosu kullanır.
   - Jenkins hash veya FNV-1 gibi hash fonksiyonları...
  
<br>Saygılarımla, @p0unter 
