<a href="https://github.com/trycatchh/protecton_defender/blob/documents/Ana%20D%C3%BC%C5%9F%C3%BCnce.md">🇹🇷 For Turkish</a>

### [Network Traffic Monitoring](https://github.com/trycatchh/protecton_defender/blob/documents/English/Listenin%20Network%20Traffic.md)
- Listens to all packets coming from the network interface (such as eth0).
- Tracks source IP addresses and packet counts.

### Anomalous Traffic Detection
- Counts the number of packets received from each IP within a specific time window (e.g., 10 seconds).
- Flags IPs that exceed a predefined threshold (e.g., 100 packets) as potential attackers.

### Blocking Mechanism
- Uses iptables (Linux firewall; different solutions apply for Windows) to block suspicious IPs.
- Applies a timeout for the blocking duration.

## Main Components and Operation
- Uses the libpcap library.
- Listens to the network card in promiscuous mode.
- For each incoming packet:
  - Extracts the source IP address.
  - Records the packet size and timestamp.

### IP Tracking System
- Example data structure for IP tracking:
```c
typedef struct {
  char ip;           // For IPv4 address.
  int packet_count;  // Number of packets in the given time window.
  time_t last_seen;  // Last seen timestamp.
} IpTracker;
```
- Creates an instance of this structure for each new IP.
- Updates counters for existing IPs.

### Attack Detection Algorithm
- Capture packet.
- Is the source IP in the packet list?
  - [YES] Increment the counter.
    - Is the counter > threshold?
      - [YES] Block the IP (iptables/firewall).
        - Reset the counter.
      - [NO] Continue.
  - [NO] Add new IP.

### Example Blocking Mechanism
- Calls iptables via a system call:
```c
void block_ip(const char *ip) {
  char command;
  snprintf(command, sizeof(command), "iptables -A INPUT -s %s -j DROP", ip); // Prepare command.
  system(command); // Execute command on the system.
  // Logging can be added...
}
```
*Note: The system() function may pose security risks and should be used carefully.*

### Time Management
- Counters are reset periodically (e.g., every 10 seconds).
- A separate thread is used for this purpose:
```c
void *reset_counters(void *arg) { // Thread function
  while(1) {
    sleep(TIME_WINDOW); // Wait 10 seconds.
    // Call counter reset function.
  }
}
```

## Solutions
1. Performance
   - Uses a hash table to handle a large number of IPs.
   - Memory management and optimization are applied.
2. Packet Types
   - Counts only specific packet types (e.g., SYN flood).
   - Takes packet sizes into consideration.
3. User Control
   - Allows users to specify which packets to count.
   - Logs analysis of blocked packets in compressed format.

### Security Measures
- Requires root privileges.
- Cleans up iptables rules.
- Generates attack detection alerts.

## Next Steps
- Advanced Algorithms:
  - Machine learning-based anomaly detection.
  - Packet content analysis.
- Distributed System:
  - Sharing IP information across multiple servers.
  - Centralized management panel.
- Protocol-Based Defense:
  - HTTP flood protection.
  - Protection against DNS amplification attacks.

Regards, @p0unter
