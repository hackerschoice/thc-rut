/*
 * arp-god :>
 */
#include "default.h"
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libnet.h>
#include "thc-rut.h"
#include "arpg.h"
#include "thcrut_sig.h"
#include "thcrut_pcap.h"


//extern struct _lnet lnet;
extern struct _opt opt;
//extern struct _pcap pcap;

libnet_ptag_t ln_arp;
libnet_ptag_t ln_eth;

/*
 * send out ARP-REPLY from ip/mac to ip/mac
 * return 0 ono success...
 */
int
send_arp(u_short proto, u_long spf_sip, u_char spf_smac[6], u_long spf_dip, u_char spf_dmac[6])
{
	int c;

	ln_arp = libnet_build_arp(ARPHRD_ETHER,
		ETHERTYPE_IP,
		6, 4, proto,
		spf_smac,
		(uint8_t *)&spf_sip,
		spf_dmac,
		(uint8_t *)&spf_dip,
		NULL,
		0,
		opt.ln_ctx, ln_arp);

	ln_eth = libnet_build_ethernet(ETHBCAST,
		spf_smac,
		ETHERTYPE_ARP,
		NULL,
		0,
		opt.ln_ctx, ln_eth);
#if 0

	libnet_build_ethernet(spf_dmac,
		spf_smac,
		ETHERTYPE_ARP,
		NULL,
		0,
		lnet.packet);

	libnet_build_arp(ARPHRD_ETHER,
		ETHERTYPE_IP,
		6,
		4,
		proto,
		spf_smac,
		(u_char *)&spf_sip,
		spf_dmac,
		(u_char *)&spf_dip,
		NULL,
		0,
		lnet.packet + LIBNET_ETH_H);
#endif

	c = libnet_write(opt.ln_ctx);

	if (c < LIBNET_ETH_H + LIBNET_ARP_H)
		ERREXIT("libnet_write() = %d, %s\n", c, libnet_geterror(opt.ln_ctx));

	return 0;
}

/*
 * called by libpcap 
 */
#if 0
static void
filter_packet(u_char *u, struct pcap_pkthdr *p, u_char *packet)
{
	static u_char *align_buf = NULL;
	struct Ether_header *eth;

	DEBUGF("filter read something\n");
	if (p->caplen < (opt.dlt_len + ETH_ARP_H))
		return;

	eth = (struct Ether_header *) (packet);

	if (align_buf == NULL)
		align_buf = (u_char *) malloc(PCAPBUFSIZE);

	memcpy(align_buf, packet + opt.dlt_len, p->caplen - opt.dlt_len);
	
	switch (ntohs(eth->ether_type))
	{
		case ETHERTYPE_IP:
			opt.handle_ip(align_buf, p->caplen - opt.dlt_len);
			break;
		case ETHERTYPE_ARP:
			opt.handle_arp(align_buf, p->caplen - opt.dlt_len);
			break;
	}

}
#endif

#if 0
void
start_arpd(const char *filter)
{
	/*
	 * We open before we fork to not loose any packets.
	 */
	opt.ip_socket = init_pcap(opt.device, 1, PCAP_FILTER, NULL, NULL, &opt.dlt_len);
	if ((opt.childpid = fork()) > 0)
		pcap_loop(opt.ip_socket, -1, (pcap_handler) filter_packet, NULL);

	pcap_close(opt.ip_socket); /* child */
	if (opt.childpid == -1)
		die(-1, "unable to fork arp-daemon");
}
#endif

