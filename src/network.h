/*
 * $Id: network.h,v 1.4 2003/05/23 14:14:01 skyper Exp $
 */


#ifndef __THCRUT_NETWORK_H__
#define __THERUT_NETWORK_H__ 1

#ifndef ETH_ALEN
# define ETH_ALEN (6)
#endif

int getmyip_by_dst(int dst);
void MAC_gen_pseudo(uint8_t *buf);
#ifndef int_ntoa
const char *int_ntoa(uint32_t ip);
#endif

#endif
