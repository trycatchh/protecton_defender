#ifndef DETECTOR_H
#define DETECTOR_H

void detect_anomaly(const char *current_ip);
void anlyze_tcp(const unsigned char *packet);

#endif // DETECTOR_H