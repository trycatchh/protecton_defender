#ifndef DETECTOR_H
#define DETECTOR_H

void detect_anomaly(const char *current_ip);
void anlyze_tcp(const unsigned char *packet);
void enhanced_detect_anomaly(const char *current_ip);
void enhanced_anlyze_tcp(const unsigned char *packet);
float get_syn_ack_ratio(const char *ip);

#endif // DETECTOR_H