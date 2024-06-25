/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN 14
#endif

u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
u_char handle_IP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
u_char handle_ICMP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet);
