#ifndef THCRUT_NETWORK_RAW_H
#define THCRUT_NETWORK_RAW_H 1

#include <sys/types.h>
/* Conflict on OpenBsd 2.8 & libnet */
/* #include <netinet/ip_icmp.h> */

#define int_ntoa(x)   inet_ntoa(*((struct in_addr *)&(x)))

#ifndef ETH_ALEN
# define ETH_ALEN	(6)
#endif

int vrfy_ip(struct ip *, uint32_t, u_short *);
int vrfy_tcp(struct tcphdr *tcp, uint32_t len, u_short *tcp_options);
int vrfy_udp(struct udphdr *, uint32_t);
int vrfy_icmp(struct icmp *, uint32_t);
char *int_ntop(char *, struct in_addr);
char *val2mac(unsigned char *);
void macstr2mac(unsigned char *dst, char *str);
int net_sock_raw(void);
int net_send(int sox, char *data, size_t len);

#endif /* !THCRUT_NETWORK_RAW_H */

