#ifndef LISTENER_H
#define LISTENER_H

#include <pcap.h>

void Listener();
void Handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif // LISTENER_H