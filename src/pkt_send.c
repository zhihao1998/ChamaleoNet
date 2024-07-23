#include "tsdn.h"

// int sock_fd;
// char *send_intf = "virbr1";

// int send_pkt(u_char *pkt, int pkt_len)
// {
//     struct sockaddr_ll sa;
//     struct ifreq ifr;
//     int ret;

//     memset(&sa, 0, sizeof(struct sockaddr_ll));
//     memset(&ifr, 0, sizeof(struct ifreq));

//     if ((sock_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1)
//     {
//         perror("Socket Error");
//         return 1;
//     }

//     strncpy(ifr.ifr_name, send_intf, IFNAMSIZ);
//     if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) == -1)
//     {
//         perror("ioctl Error");
//         return 1;
//     }

//     sa.sll_family = AF_PACKET;
//     sa.sll_protocol = htons(ETH_P_ALL);
//     sa.sll_ifindex = ifr.ifr_ifindex;

//     ret = sendto(sock_fd, pkt, pkt_len, 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll));
//     if (ret == -1)
//     {
//         perror("Sendto Error");
//         return 1;
//     }

//     close(sock_fd);
//     return 0;
// }