/*
 * $Id: packets.c,v 1.7 2003/05/23 14:14:01 skyper Exp $
 */

#include "default.h"
#include <libnet.h>
#include <time.h>
#include "nmap_compat.h"
#include "fp.h"
#include "thc-rut.h"
#include "dhcp.h"

extern struct _opt opt;
extern uint8_t ip_tcp_sync[];
extern uint8_t ip_tcp_fp[];
extern uint8_t ip_udp_dcebind[];
extern uint8_t ip_udp_snmp[];
extern uint8_t ip_icmp_echo[];
extern unsigned short ip_tcp_sync_chksum;
extern unsigned short ip_tcp_fp_chksum;

/*
 * Pre-generate packets for the scanner.
 * opt.src_ip is 0.0.0.0 and filled by the kernel.
 * (We dont know the src_ip yet).
 */
void
scanner_gen_packets(void)
{
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmphdr *icmp;

	tcp = (struct tcphdr *)ip_tcp_sync;
	tcp->source = htons(opt.src_port);
	tcp->dest = htons(80);
	tcp->seq = htonl(0xffffffff - time(NULL));
	tcp->syn = 1;
	tcp->window = 5840;
	tcp->check = 0;

	/* Port wrapps around every 4096 seconds */
#if 0
	libnet_build_tcp(opt.src_port,
			80,
			0xffffffff - time(NULL),
			0x0,
			TH_SYN,
			5840,
			0,
			NULL,
			0, ip_tcp_sync);
#endif
#if 0
	libnet_build_ip(LIBNET_TCP_H,
			IPTOS_RELIABILITY,
			opt.ip_id,  /* for outgoing ip's only */
			0,
			255,
			IPPROTO_TCP,
			opt.src_ip,
			0 /*dst*/,
			NULL,
			0,
			ip_tcp_sync);
	libnet_do_checksum(ip_tcp_sync, IPPROTO_TCP, LIBNET_TCP_H);
	ip_tcp_sync_chksum = *(unsigned short *)(ip_tcp_sync + 36);
#endif

	tcp = (struct tcphdr *)ip_tcp_fp;
	tcp->source = htons(opt.src_port + 1);
	tcp->dest = htons(80);
	tcp->seq = htonl(0xffffffff - time(NULL) + 1);
	tcp->syn = 1;
	tcp->window = 5840;
	tcp->check = 0;
#if 0
	libnet_build_tcp(opt.src_port + 1,
			0,
			0xffffffff - time(NULL) + 1,
			0x0,
			TH_SYN,
			5840,
			0,
			NULL,
			0, ip_tcp_fp);
	tcp = (struct tcphdr *)(ip_tcp_fp);
#endif
	tcp->doff = (20 + NMAP_FP_TONE_LEN) >> 2;
	memcpy(ip_tcp_fp + 20, NMAP_FP_TONE, NMAP_FP_TONE_LEN);
#if 0
	libnet_build_ip(LIBNET_TCP_H + NMAP_FP_TONE_LEN,
			IPTOS_RELIABILITY,
			opt.ip_id,  /* for outgoing ip's only */
			0,
			255,
			IPPROTO_TCP,
			opt.src_ip,
			0 /*dst*/,
			NULL,
			0,
			ip_tcp_fp);
#endif

	udp = (struct udphdr *)ip_udp_dcebind;
	udp->source = htons(opt.src_port + 1);
	udp->len = htons(FP_DCEBIND_LEN);
	memcpy(ip_udp_dcebind + 8, FP_DCEBIND, FP_DCEBIND_LEN);

#if 0
	libnet_build_udp(opt.src_port + 1,
			0,
			NULL,
			FP_DCEBIND_LEN,
			ip_udp_dcebind);
#endif
#if 0
	libnet_build_ip(LIBNET_UDP_H + FP_DCEBIND_LEN,
			IPTOS_RELIABILITY,
			opt.ip_id,  /* for outgoing ip's only */
			0,
			255,
			IPPROTO_UDP,
			opt.src_ip,
			0 /*dst*/,
			NULL,
			0,
			ip_udp_dcebind);
#endif

	udp = (struct udphdr *)ip_udp_snmp;
	udp->source = htons(opt.src_port + 1);
	udp->dest = htons(161);
	udp->len = htons(FP_SNMP_LEN);
#if 0	
	libnet_build_udp(opt.src_port + 1,
			161,
			NULL,
			FP_SNMP_LEN,
			ip_udp_snmp);
#endif
	memcpy(ip_udp_snmp + LIBNET_UDP_H, FP_SNMP, FP_SNMP_LEN);
#if 0
	libnet_build_ip(LIBNET_UDP_H + FP_SNMP_LEN,
			IPTOS_RELIABILITY,
			opt.ip_id,  /* for outgoing ip's only */
			0,
			255,
			IPPROTO_UDP,
			opt.src_ip,
			0 /*dst*/,
			NULL,
			0,
			ip_udp_snmp);
#endif

	icmp = (struct icmphdr *)ip_icmp_echo;
	icmp->type = ICMP_ECHO;		/* 8 */
	icmp->un.echo.id = htons(getpid());
	icmp->un.echo.sequence = 1;
#if 0
	libnet_build_icmp_echo(8,
			0,
			htons(getpid()), /* we match for this ID! */
			1,
			NULL,
			0,
			ip_icmp_echo);
#endif
#if 0
	libnet_build_ip(8,
			IPTOS_RELIABILITY,
			opt.ip_id,  /* for outgoing ip's only */
			0,
			255,
			IPPROTO_ICMP,
			opt.src_ip,
			0 /*dst*/,
			NULL,
			0,
			ip_icmp_echo);
#endif

}

void
dhcp_gen_packets(uint8_t *packet, uint32_t srcip, uint8_t *dsbuf, struct _dhcpset *ds)
{
#if 0
	int len;

	libnet_build_udp(68,
			67,
			NULL,
			datalen - 8,  /* length */
			packet + LIBNET_ETH_H + LIBNET_IP_H);

	libnet_build_ip(datalen,  /* length of ip DATA */
			0,
			7350,
			0,
			128,
			IPPROTO_UDP,
			srcip,  /* source IP      */
			-1,     /* Destination IP */
			NULL,
			0,
			packet + LIBNET_ETH_H);

	libnet_build_ethernet(ETHBCAST,
			"\x00\x00\x00\x00\x00\x00",
			ETHERTYPE_IP,
			NULL,
			0,
			packet);
#endif

	build_bootp(packet, ETHZCAST, LIBNET_ETH_H);
	dhcp_add_option(ds, DHCP_END, 0, NULL);
	memcpy(packet + sizeof(struct _bootp), dsbuf, ds->lsize);
}

void
arp_gen_packets(unsigned int srcip)
{
#if 0
	opt.ln_arp = libnet_build_arp(ARPHRD_ETHER,
			ETHERTYPE_IP,
			6,
			4,
			ARPOP_REQUEST,
			ETHZCAST,
			(unsigned char *)&srcip,
			ETHBCAST,
			"\x00\x00\x00\x00", /* IP */
			NULL,
			0,
			opt.ln_ctx, opt.ln_arp);

	opt.ln_eth = libnet_build_ethernet(ETHBCAST,
			ETHZCAST,
			ETHERTYPE_ARP,
			NULL,
			0,
			opt.ln_ctx, opt.ln_eth);
#endif
}

void
icmp_gen_packets(uint8_t *pe, int pe_s, uint8_t *pa, int pa_s, uint8_t *pr, int pr_s)
{
	struct icmphdr *icmp;

	icmp = (struct icmphdr *)pe;
	icmp->type = ICMP_ECHO;
	icmp->un.echo.id = htons(getpid());
	icmp->un.echo.sequence = 1;

#if 0
	libnet_build_icmp_echo(8,
			0,
			htons(getpid()), /* we match for this ID! */
			1,
			NULL,
			0,
			pe);
#endif

	icmp = (struct icmphdr *)pa;
	icmp->type = ICMP_ADDRESS;
	icmp->un.echo.id = htons(getpid());
	icmp->un.echo.sequence = 1;

#if 0
	libnet_build_icmp_mask(17,  /* Address Mask request */
			0,
			htons(getpid()),
			1,
			0,
			NULL,
			0,
			pa);
#endif

#if 0
	libnet_build_ip(0,
			IPTOS_RELIABILITY,
			opt.ip_id, /* for outgoing ip's only */
			0,
			255,
			IPPROTO_ICMP,
			opt.src_ip,
			0 /*dst*/,
			NULL,
			0,
			pe);
	memcpy(pa, pe, 20);
	memcpy(pr, pe, 20);
	((struct ip *)pe)->ip_len = htons(pe_s);
	((struct ip *)pa)->ip_len = htons(pa_s);
	((struct ip *)pr)->ip_len = htons(pr_s);
#endif

	icmp = (struct icmphdr *)pr;
	icmp->type = ICMP_ROUTERSOLICIT;
}
