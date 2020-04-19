/*
 * $Id: thcrut_libnet.h,v 1.2 2003/05/23 14:14:02 skyper Exp $
 */

#include <libnet.h>

#ifndef __THCRUT_THCRUT_LIBNET_H__
#define __THCRUT_THCRUT_LIBNET_H__ 1

struct libnet_link_int *init_libnet(char **device, int *src_ip);
void fini_libnet(struct libnet_link_int *network);

#endif /* !__THCRUT_THCRUT_LIBNET_H__ */
