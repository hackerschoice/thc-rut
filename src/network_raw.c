/*
 * $Id: network_raw.c,v 1.8 2003/05/23 14:14:01 skyper Exp $
 */
#include "default.h"
#include "fcntl.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <libnet.h>
#include "network_raw.h"

/*
 * len of the data we got. We might have less options here.
 * (rest is payload).
 */
int
vrfy_tcp(struct tcphdr *tcp, uint32_t len, u_short *tcp_options)
{
	u_short _tcp_options;

	if (len < sizeof *tcp)
		return -1;
	_tcp_options = tcp->th_off << 2;
	if (_tcp_options < sizeof *tcp)
		return -1;

	if (_tcp_options > len)
		return -1;

	if (tcp_options)
		*tcp_options = _tcp_options - sizeof *tcp;

	return 0;
}

/*
 * return 0 if ip-header is valid [length only]
 * len = length from the begin of the ip-header [20 for normal ip header]
 */
int
vrfy_ip(struct ip *ip, uint32_t len, u_short *ip_options)
{
	u_short _ip_options;
    
	if (len < sizeof *ip)
		return -1;
	_ip_options = ip->ip_hl << 2;

	if (_ip_options < sizeof *ip)
		return -1;

	if (_ip_options > len)
		return -1;

	if (_ip_options > 0xefff)   /* NO, we dont accept this ! */
		return -1;

	if (ip_options)
		*ip_options = _ip_options - sizeof *ip;

	return 0;
}

int
vrfy_udp(struct udphdr *udp, uint32_t len)
{
	if (len < sizeof(*udp))
		return -1;

	return 0;
}

/*
 * return 0 if header is valid
 * return -1 if not 
 * and -2 is unknown
 * this function should _only_ be used with thc-rut!
 * this function is _not_ portable...we only check for icmp-codes/types
 * we are interested in.
 */
int
vrfy_icmp (struct icmp *icmp, uint32_t len)
{
    if (len < ICMP_MINLEN)
        return (-1);

    switch (icmp->icmp_type)
    {
        case ICMP_MASKREPLY:
            if (icmp->icmp_code != 0)
                return -2;
            if (len >= ICMP_MASKLEN)
                return 0;
            else
                return -1;
            /* check _ALL_ icmp_type == 18 types HERE */
            return -2;
        case ICMP_ECHOREPLY:
            if (icmp->icmp_code == 0)
                return 0;
            return -2;
        case ICMP_ECHO:
            if (icmp->icmp_code == 0)
                return 0;
            return -2;
            break;
        default:
            return -2;      /* header invalid if type/code not known */
    }

    return 0;
}

/*
 * slow inet_ntoa but in function-supplied buffer and not
 * static buffer like inet_ntoa
 */
char *
int_ntop(char *buf, struct in_addr in)
{

	sprintf(buf, "%s", inet_ntoa(*((struct in_addr *)&(in))));

	return buf;
}


/*
 * convert a mac to a colon seperated string
 */
char *
val2mac(unsigned char *ptr)
{
	static char buf[64];

	sprintf(buf, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
		(u_char)ptr[0],
		(u_char)ptr[1],
		(u_char)ptr[2],
		(u_char)ptr[3],
		(u_char)ptr[4],
		(u_char)ptr[5]);

	return buf;
}

void
init_ip(char *buf)
{

}

void
init_tcp(char *buf)
{

}

void
macstr2mac(unsigned char *dst, char *str)
{
	unsigned short int sp[ETH_ALEN];
	int c = ETH_ALEN;

	memset(&sp, 0, sizeof sp);
	sscanf(str, "%hx:%hx:%hx:%hx:%hx:%hx",  &sp[0], &sp[1], &sp[2],&sp[3], &sp[4], &sp[5]);

	while (c-- > 0)
		dst[c] = (unsigned char)sp[c];
}

/*
 * Open an UNBLOCKING RAW socket used for sending.
 */
libnet_t *
net_sock_raw(void)
{
	libnet_t *ln_ctx;

	ln_ctx = libnet_init(LIBNET_RAW4_ADV, NULL, NULL);
	return ln_ctx;
#if 0
	int sox;
	int i;

	sox = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sox < 0)
		return -1;
	i = 1;
	setsockopt(sox, IPPROTO_IP, IP_HDRINCL, (int *)&i, sizeof i);
	i = 10 * 1024 * 1024; /* Limited by system MAX anyway */
	setsockopt(sox, SOL_SOCKET, SO_SNDBUF, &i, sizeof i);
	fcntl(sox, F_SETFL, fcntl(sox, F_GETFL, 0) | O_NONBLOCK);

	return sox;
#endif
}

/*
 * Return the number of bytes written.
 * This function can exit.
 *
 * Return -1 on error. Return 0 if would_block.
 */
size_t
net_send(libnet_t *ln_ctx)
{
	size_t len;
#ifdef DEBUG
	static char full_once;
#endif

	len = libnet_write(ln_ctx);
	if (len <= 0)
	{
#if 0
		/* No arp reply [local netowrk scan] */
		if (errno == EHOSTDOWN)
			return -1;
		/* Linux: No route to network [no default gw] */
		if (errno == ENETUNREACH)
			return -1;
		/* OpenBSD: No route to host [no default gw] */
		if (errno == EHOSTUNREACH)
			return -1;
#endif
		/*
		 * The Problem: When scanning local networks. The buffer
		 * buffers all the data and tries to resolve the arp.
		 * We cant say (from userland) if the buffer is full because
		 * the kernel is still trying to resolve the mac or if the buffer
		 * is full because the kernel still sends.
		 *
		 * Needed: On error decide if the packet has already been
		 * retransmitted for 3 times and discard _only_ if the kernel
		 * failed to do so because the mac could not be resolved.
		 *
		 * Return error whenever it's something different than buffer-full.
		 *
		 * OpenBSD 2.8 returns EMSGSIZE(40) if buf full
		 * OpenBSD 2.8 returns ENONET(64) if arp unresolved
		 *
		 * Linux returns EACCESS if tcp send to broadcast (10.2.0.0)
		 */
		if ((errno != ENOBUFS) && (errno != EMSGSIZE))
		{
			DEBUGF("WRITE ERROR (%d)%s\n", errno, strerror(errno));
			return -1;
		}

#ifdef DEBUG
		if (!full_once)
		{
			fprintf(stderr, ""
"WARNING: send buffer full. A kernel buffer most probably ran out of memory\n"
"while resolving the mac's (scanning local network, eh?). Waiting until\n"
"more buffer space becomes available...\n");
			full_once = 1;
		}
#endif
		return 0;
	}

	return len;
}

