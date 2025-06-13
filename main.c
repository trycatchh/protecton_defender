#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

char errbuf[PCAP_ERRBUF_SIZE];

int main() {
    pcap_if_t *alldevs, *device;
    char *dev_name;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[ERR] Not found interface: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    if (alldevs == NULL) {
        fprintf(stderr, "[ERR] Not found interface\n");
        exit(EXIT_FAILURE);
    }
    
    dev_name = alldevs->name;
    printf("Listening interface: %s\n", dev_name);
    
    pcap_t *handle = pcap_open_live(
        dev_name,
        BUFSIZ,
        1,
        1000,
        errbuf
    );
    
    if (handle == NULL) {
        fprintf(stderr, "[ERR] Not opened interface: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        exit(EXIT_FAILURE);
    }
    
    printf("Interface opened!\n");
    
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    
    return 0;
}