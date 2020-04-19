/*
 * $Id: packets.c,v 1.7 2003/05/23 14:14:01 skyper Exp $
 */

#include "default.h"
#include <libnet.h>
#include <time.h>
#include "nmap_compat.h"
#include "fp.h"
#include "thcrut.h"
#include "dhcp.h"

extern struct _opt opt;
extern char ip_tcp_sync[];
extern char ip_tcp_fp[];
extern char ip_udp_dcebind[];
extern char ip_udp_snmp[];
extern char ip_icmp_echo[];
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

	/* Port wrapps around every 4096 seconds */
	libnet_build_tcp(opt.src_port,
			80,
			0xffffffff - time(NULL),
			0x0,
			TH_SYN,
			5840,
			0,
			NULL,
			0, ip_tcp_sync + LIBNET_IP_H);
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

	libnet_build_tcp(opt.src_port + 1,
			0,
			0xffffffff - time(NULL) + 1,
			0x0,
			TH_SYN,
			5840,
			0,
			NULL,
			0, ip_tcp_fp + LIBNET_IP_H);
	tcp = (struct tcphdr *)(ip_tcp_fp + 20);
	tcp->th_off = (20 + NMAP_FP_TONE_LEN) >> 2;
	memcpy(ip_tcp_fp + 40, NMAP_FP_TONE, NMAP_FP_TONE_LEN);
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

	memcpy(ip_udp_dcebind + 20 + LIBNET_UDP_H, FP_DCEBIND, FP_DCEBIND_LEN);
	libnet_build_udp(opt.src_port + 1,
			0,
			NULL,
			FP_DCEBIND_LEN,
			ip_udp_dcebind + LIBNET_IP_H);
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

	libnet_build_udp(opt.src_port + 1,
			161,
			NULL,
			FP_SNMP_LEN,
			ip_udp_snmp + LIBNET_IP_H);
	memcpy(ip_udp_snmp + 20 + LIBNET_UDP_H, FP_SNMP, FP_SNMP_LEN);
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

	libnet_build_icmp_echo(8,
			0,
			htons(getpid()), /* we match for this ID! */
			1,
			NULL,
			0,
			ip_icmp_echo + LIBNET_IP_H);
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

}

void
dhcp_gen_packets(char *packet, int datalen, unsigned int srcip, char *dsbuf, struct _dhcpset *ds)
{
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

	len = LIBNET_ETH_H + LIBNET_IP_H + LIBNET_UDP_H;
	build_bootp(packet + len, ETHZCAST, LIBNET_ETH_H);
	dhcp_add_option(ds, DHCP_END, 0, NULL);
	memcpy(packet + len + sizeof(struct _bootp), dsbuf, ds->lsize);
}

void
arp_gen_packets(char *packet, unsigned int srcip)
{
	libnet_build_arp(ARPHRD_ETHER,
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
			packet + LIBNET_ETH_H);

	libnet_build_ethernet(ETHBCAST,
			ETHZCAST,
			ETHERTYPE_ARP,
			NULL,
			0,
			packet);
}

void
icmp_gen_packets(char *pe, int pe_s, char *pa, int pa_s, char *pr, int pr_s)
{
	libnet_build_icmp_echo(8,
			0,
			htons(getpid()), /* we match for this ID! */
			1,
			NULL,
			0,
			pe + LIBNET_IP_H);


	libnet_build_icmp_mask(17,  /* Address Mask request */
			0,
			htons(getpid()),
			1,
			0,
			NULL,
			0,
			pa + LIBNET_IP_H);

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

	*(pr + 20) = 10;  /* Router solicitation */
}
