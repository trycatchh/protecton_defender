<a href="https://github.com/trycatchh/protecton_defender/blob/documents/A%C4%9F%20Trafi%C4%9Fini%20Dinleme.md">🇹🇷 For Turkish</a>

### Listening to Network Traffic
In C language, the traditional way to listen to network traffic is by using the Libpcap library. This is the industry-standard approach for capturing network packets.

### Basic Steps
1. Libpcap
   - **Promiscuous Mode:** The network interface listens to all traffic.
   - **Packet Filtering:** Capture only the traffic of interest using BPF (Berkeley Packet Filter).
   - **Callback Mechanism:** A function automatically called when a packet is captured.
2. Basic Workflow:
   - Initialize Libpcap
   - Select Network Interface
   - Create Packet Capture Handle
   - Set Filter Rules
   - Packet Capture Loop
   - Packet Processing Function
3. Detailed Steps
   - Starting Libpcap
   ```c
   #include 
   char errbuf[PCAP_ERRBUF_SIZE]; // For error messages...
   ```
   - Selecting Network Interface
   ```c
   // Automatically find the default interface:
   char *device = pcap_lookupdev(errbuf);
   if (!device) {
       fprintf(stderr, "Interface not found: %s\n", errbuf);
       return 1;
   }
   printf("Listening on interface: %s\n", device);
   ```
   - Creating Packet Capture Handle
   ```c
   pcap_t *handle = pcap_open_live(
       device,   // Network interface.
       BUFSIZ,   // Maximum packet size.
       1,        // Promiscuous mode (1 = enabled)
       1000,     // Timeout (ms)
       errbuf    // Error buffer.
   );
   ```
   - Setting Filter
   ```
   struct bpf_program fp;
   char filter_exp[] = "tcp"; // Only TCP packets.
   bpf_u_int32 subnet_mask, ip;

   // Get network address info.
   pcap_lookupnet(device, &ip, &subnet_mask, errbuf);

   // Compile the filter
   pcap_compile(handle, &fp, filter_exp, 0, ip);
   pcap_setfilter(handle, &fp);
   ```
   - Packet Processing Function
   ```c
   void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
       // Packet processing code...
       printf("Captured packet size: %d\n", header->len);
   }
   ```

## Parsing Packet Structure
To make packets meaningful, a typical Ethernet packet structure:

```c
struct ethheader {
    u_char  ether_dhost[6]; // Destination MAC
    u_char  ether_shost[6]; // Source MAC
    u_short ether_type;     // Protocol type (IPv4: 0x0800)
};

struct ipheader {
    u_char  iph_ihl:4;      // IP header length
    u_char  iph_ver:4;      // IP version
    u_char  iph_tos;        // Type of service
    u_short iph_len;        // Total length
    u_short iph_ident;      // Identification
    u_short iph_flag:3;     // Fragmentation flags
    u_short iph_offset:13;  // Fragment offset
    u_char  iph_ttl;        // Time to live
    u_char  iph_protocol;   // Protocol (TCP=6, UDP=17)
    u_short iph_chksum;     // Checksum
    struct in_addr iph_sourceip;  // Source IP
    struct in_addr iph_destip;    // Destination IP
};

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    
    // Only IPv4 packets
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        
        printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
        
        // TCP packets
        if (ip->iph_protocol == IPPROTO_TCP) {
            // Parse TCP header
        }
    }
}
```

### Notes
1. Performance Optimization
   - Uses static memory for large data.
2. Different Protocols
   - TCP: `struct tcphdr` (netinet/tcp.h)
   - UDP: `struct udphdr` (netinet/udp.h)
   - ICMP: `struct icmphdr` (netinet/ip_icmp.h)
3. Hash Table Optimization
   - Uses hash tables for IP tracking at large scale.
   - Hash functions like Jenkins hash or FNV-1...

Best regards, @p0unter
