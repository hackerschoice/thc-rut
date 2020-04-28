/*
 * $Id: thcrut_pcap.c,v 1.10 2003/05/25 18:19:16 skyper Exp $
 */

#include "default.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "thcrut_pcap.h"

#ifndef int_ntoa
# define int_ntoa(x)   inet_ntoa(*((struct in_addr *)&(x)))
#endif

extern struct _opt opt;
static char err_buf[PCAP_ERRBUF_SIZE];

#define PCAPERREXIT(a...) do{ \
	fprintf(stderr, a); fprintf(stderr, ": %s\n", err_buf); \
	exit(-1); \
}while(0)

static int
dltlen_get(int type)
{
	switch (type)
	{
	case DLT_NULL:
	case DLT_PPP:
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
#ifdef DLT_C_HDLC
	case DLT_C_HDLC:
#endif
#ifdef DLT_PPP_SERIAL
	case DLT_PPP_SERIAL:
#endif
		return 4;
	case DLT_ARCNET:
		return 6;
#ifdef DLT_PPP_ETHER
	case DLT_PPP_ETHER:
		return 8;
#endif
	case DLT_SLIP:
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:  /* -i any -device */
#endif
		return 16;
	case DLT_PPP_BSDOS:
	case DLT_SLIP_BSDOS:
		return 24;
#ifdef DLT_PRISM_HEADER
	case DLT_PRISM_HEADER:
		return 144+30;
#endif
#ifdef DLT_IEEE802_11
	case DLT_IEEE802_11:
		return 30;	/* FIXME: what's the fuzz about snap mode
				   or not snap mode? */
#endif
#ifdef DLT_IEEE802
	case DLT_IEEE802:
		return 22;
#endif
	case DLT_RAW:
		return 0;
	}

	return 14;  /* DEFAULT :/ DLT_EN10MB */
}

/*
 * init sniffer (we need this to read arp-requests to our spoofed address
 * FIXME: return a struct here...
 */
pcap_t *
init_pcap(char *device, int promisc, char *filter, long *net, long *bcast, int *dltlen)
{
	struct bpf_program prog;
	bpf_u_int32 network, netmask;
	pcap_t *ip_socket;

	/* Fucking pcap developer idiots. They changed the behavior
	 * of pcap_open_live() to open 'any' interface and not
	 * the first network interface. This basicly fucked up all code
	 * which relied on the returned bcast to be the bcast of the local
	 * network.
	 */
	if (!device)
	{
		pcap_if_t *ifcs;
		if (pcap_findalldevs(&ifcs, err_buf) == -1)
			PCAPERREXIT("pcap_findalldevs()");
		device = ifcs->name;
#if 0
		if (!(device = pcap_lookupdev(err_buf)))
			PCAPERREXIT("pcap_lookupdev");
#endif
	}
	if ((net) || (bcast))
	{
		if (pcap_lookupnet(device, &network, &netmask, err_buf) < 0)
			PCAPERREXIT("pcap_lookupnet");
		if (net)
			*net = ntohl(network);
		if (bcast)
			*bcast = ntohl(network + ~netmask);
	}

	/* FIXME: tcpdump sets it to 1,000 wich is to large?! */
	/* Must set to != 0 or FreeBSD at least will never return. */
	/* It seems to be ignored under linux at least. We want pcap to
	 * return immediatly anyway.
	 * We set buffer to 8k, any larger value makes the programm slower.
	 */
	ip_socket = pcap_open_live(device, 8192, promisc, 1, err_buf);
	if (!ip_socket)
		PCAPERREXIT("pcap_open_live");

	if (filter)
	{
		if (pcap_compile(ip_socket, &prog, filter, 1, netmask) < 0)
			PCAPERREXIT("pcap_compile");

		if (pcap_setfilter(ip_socket, &prog) < 0)
			PCAPERREXIT("pcap_setfilter");
	}

	if (dltlen)
		*dltlen = dltlen_get(pcap_datalink(ip_socket));

	fprintf(stderr, "thcrut: listening on %s\n", device);

	return ip_socket;
}

/*
 * The stats are reset to 0 after querying (at least on Linux).
 * We dont want this to happen.
 */
int
thcrut_pcap_stats(pcap_t *p, struct pcap_stat *ps)
{
	static unsigned int recv, drop;
	int ret;

	ret = pcap_stats(p, ps);
	if (ret != 0)
		return ret;

	recv += ps->ps_recv;
	drop += ps->ps_drop;
	ps->ps_recv = recv;
	ps->ps_drop = drop;

	return 0;
}

