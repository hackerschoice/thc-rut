/*
 * $Id: thcrut_libnet.c,v 1.2 2003/05/23 14:14:02 skyper Exp $
 */

#include "default.h"
#include <libnet.h>

#define int_ntoa(x) inet_ntoa(*((struct in_addr *)&(x)))

libnet_t *
init_libnet(char *device/*, int *ip*/)
{
	char err_buf[LIBNET_ERRBUF_SIZE];
	libnet_t *ln_ctx;

	err_buf[0] = 0;
#if 0
	if ((device == NULL) || (*device == NULL))
	{
		struct sockaddr_in sin;

		if (libnet_select_device(&sin, &mydev, err_buf) == -1)
			libnet_error(LIBNET_ERR_FATAL, "libnet_select_device: %s\n", err_buf);
	} else {
		mydev = *device;
	}

	if (strcmp(mydev, "any") == 0)
		return NULL;
#endif

	ln_ctx = libnet_init(LIBNET_LINK_ADV, device, err_buf);
	//network = libnet_open_link_interface(mydev, err_buf);
	if (!ln_ctx)
		ERREXIT("libnet_init(): %s\n", err_buf);


#if 0
	if (ip)
	{
		if (!*ip)
			*ip = htonl(libnet_get_ipaddr(network, mydev, err_buf));
		if (*ip)
			fprintf(stderr, "thcrut: using source ip %s\n", int_ntoa(*ip));
	}
#endif

	return ln_ctx;
}

void
fini_libnet(libnet_t *ln_ctx)
{
	libnet_destroy(ln_ctx);
}

