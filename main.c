#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h> // Added for getuid()

#include "network/listener.h"
#include "network/detector.h"
#include "network/blocker.h"

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    printf("\n[MAIN] Received signal %d, shutting down gracefully...\n", sig);
    
    // Cleanup operations here
    // - Close pcap handle
    // - Stop threads
    // - Clean iptables rules if needed
    
    exit(EXIT_FAILURE);
}

int main() {
    printf("[MAIN] Starting Integrated DDoS Protection System...\n");
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Check if running as root (required for iptables and packet capture)
    if (getuid() != 0) {
        fprintf(stderr, "[MAIN/ERR] This program must be run as root!\n");
        return 1;
    }
    
    printf("[MAIN] System initialized. Starting packet capture...\n");
    
    // Start enhanced listener with integrated blocking
    enhanced_listener_interface();
    
    return 0;
}