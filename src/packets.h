/*
 * $Id: packets.h,v 1.4 2003/05/23 14:14:01 skyper Exp $
 */


#ifndef __THCRUT_PACKETS_H__
#define __THCRUT_PACKETS_H__ 1

#include "dhcp.h"

void scanner_gen_packets(void);
void dhcp_gen_packets(char *packet, int iptotlen, unsigned int srcip, char *dsbuf, struct _dhcpset *ds);
void arp_gen_packets(char *packet, unsigned int srcip);
void icmp_gen_packets(char *pe, int pe_s, char *pa, int pa_s, char *pr, int pr_s);

#endif
