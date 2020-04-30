#ifndef THCRUT_NETWORK_RAW_H
#define THCRUT_NETWORK_RAW_H 1

#include <sys/types.h>
/* Conflict on OpenBsd 2.8 & libnet */
/* #include <netinet/ip_icmp.h> */
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

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
libnet_t *net_sock_raw(void);
size_t net_send(libnet_t *ln_ctx);

#endif /* !THCRUT_NETWORK_RAW_H */

