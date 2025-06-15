#ifndef LISTENER_H
#define LISTENER_H

#include <pcap.h>

void listener_interface();
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void enhanced_packet_handler(unsigned char *args __attribute__((unused)), const struct pcap_pkthdr *header, const unsigned char *packet);
void enhanced_listener_interface();

#endif // LISTENER_H