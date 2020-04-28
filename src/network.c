/*
 * $Id: network.c,v 1.4 2003/05/23 14:14:01 skyper Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "network.h"

/*
 */
void
MAC_gen_pseudo(uint8_t *buf)
{
	uint32_t r = rand();

	buf[2] = (r >> 24) & 0xFF;
	buf[3] = (r >> 16) & 0xFF;
	buf[4] = (r >> 8) & 0xFF;
	buf[5] = r & 0xFF;
#if 0
	long l = time(NULL);

	if (l & 0x100) /* change vendor every 256 seconds */
		memcpy(buf, "\x00\x10\x66\x66\x66\x66", 6);
	else
		memcpy(buf, "\x00\x01\x66\x73\x50", 5);
	buf[2] = (l >> 8) & 0xFF;
	buf[3] = (l >> 10) & 0xFF;
	buf[4] = (l >> 7) & 0xFF;
	buf[5] = (l >> 9) & 0xFF;
#endif
}

/*
 * Lame routine to get our own src address.
 * dst is in NBO.
 * Return IP in NBO.
 *
 * FIXME: This wont work if no default gw exist!
 * We have to lookup ip from device.
 */
int
getmyip_by_dst(int dst)
{
	int sox = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in sock;
	socklen_t socklen = sizeof(struct sockaddr_in);

	sock.sin_family = AF_INET;
	sock.sin_addr.s_addr = dst;
	sock.sin_port = 7350;

	connect(sox, (struct sockaddr *)&sock, sizeof sock);
	if (getsockname(sox, (struct sockaddr *)&sock, &socklen) == -1)
		sock.sin_addr.s_addr = 0;

	close(sox);
	return sock.sin_addr.s_addr;
}

#ifndef int_ntoa
const char *
int_ntoa(uint32_t ip)
{
        struct in_addr in;

        in.s_addr = ip;
        return inet_ntoa(in);
}
#endif

