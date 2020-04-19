/*
 * $Id: thcrut_libnet.c,v 1.2 2003/05/23 14:14:02 skyper Exp $
 */

#include <libnet.h>

#define int_ntoa(x) inet_ntoa(*((struct in_addr *)&(x)))

struct libnet_link_int *
init_libnet(char **device, int *ip)
{
	char err_buf[LIBNET_ERRBUF_SIZE];
	struct libnet_link_int *network;
	char *mydev = NULL;

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

	network = libnet_open_link_interface(mydev, err_buf);
	if (!network)
		libnet_error(LIBNET_ERR_FATAL, "libnet_open_link_interface: %s\n", err_buf);

	if (device)
		*device = mydev;

	if (ip)
	{
		if (!*ip)
			*ip = htonl(libnet_get_ipaddr(network, mydev, err_buf));
		if (*ip)
			fprintf(stderr, "thcrut: using source ip %s\n", int_ntoa(*ip));
	}

	return network;
}

void
fini_libnet(struct libnet_link_int *network)
{
	libnet_close_link_interface(network);
}

