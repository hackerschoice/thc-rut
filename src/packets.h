/*
 * $Id: packets.h,v 1.4 2003/05/23 14:14:01 skyper Exp $
 */


#ifndef __THCRUT_PACKETS_H__
#define __THCRUT_PACKETS_H__ 1

#include "dhcp.h"

void scanner_gen_packets(void);
void dhcp_gen_packets(uint8_t *packet, uint32_t srcip, uint8_t *dsbuf, struct _dhcpset *ds);
void arp_gen_packets(unsigned int srcip);

#endif
