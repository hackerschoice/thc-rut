/*
 * $Id: thcrut_libnet.c,v 1.2 2003/05/23 14:14:02 skyper Exp $
 */

#include "default.h"
#include <libnet.h>

#define int_ntoa(x) inet_ntoa(*((struct in_addr *)&(x)))

libnet_t *
init_libnet(char *device, uint32_t *ip)
{
	char err_buf[LIBNET_ERRBUF_SIZE];
	libnet_t *ln_ctx;

	err_buf[0] = 0;

	ln_ctx = libnet_init(LIBNET_LINK_ADV, device, err_buf);
	if (!ln_ctx)
		ERREXIT("libnet_init(): %s\n", err_buf);


#if 1
	if (ip)
	{
		if (*ip == 0)
			*ip = libnet_get_ipaddr4(ln_ctx);
		if (*ip)
			fprintf(stderr, "thc-rut: using source ip %s\n", int_ntoa(*ip));
	}
#endif

	return ln_ctx;
}

void
fini_libnet(libnet_t *ln_ctx)
{
	libnet_destroy(ln_ctx);
}

