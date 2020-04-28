/*
 * $Id: thcrut_libnet.h,v 1.2 2003/05/23 14:14:02 skyper Exp $
 */

#include <libnet.h>

#ifndef __THCRUT_THCRUT_LIBNET_H__
#define __THCRUT_THCRUT_LIBNET_H__ 1

libnet_t *init_libnet(char *device, uint32_t *src_ip);
void fini_libnet(libnet_t *ln_ctx);

#endif /* !__THCRUT_THCRUT_LIBNET_H__ */
