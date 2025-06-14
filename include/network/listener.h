#ifndef LISTENER_H
#define LISTENER_H

#include <pcap.h>

void listener_interface();
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif // LISTENER_H