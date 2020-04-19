/*
 * $Id:$
 */

#include "default.h"
#include <sys/types.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <libnet.h>
#include "thcrut.h"
#include "dhcp.h"
#include "thcrut_libnet.h"
#include "network_raw.h"
#include "network.h"
#include "range.h"
#include "dhcp.h"
#include "packets.h"
#include "thcrut_pcap.h"

#define STATE_RESET		(0)
#define STATE_DHCPI		(1)
#define STATE_DHCPII		(2)
#define STATE_DHCPIII		(3)

#define DFL_HOSTS_PARALLEL      (10)

extern struct _opt opt;
static void dhcp_filter(unsigned char *u, struct pcap_pkthdr *p, unsigned char *packet);

static struct _lnet lnet;
//static struct _bmac bmac;
static struct _dhcpset ds;
static char dsbuf[1024];
static char buf_packet[1024];
static char *packet; /* Aligned so that ip-header is on a 4byte boundary */
static unsigned char srcmac[ETH_ALEN];

/*
 * Print out the last suboptions (one:value two:value, ..)
 * We trust the input (no error checking)
 */
static void
dhcp_print_lastsub(struct _dhcpset *ds)
{   
	unsigned char len;    /* number of suboptions */
	unsigned char *ptr;
	unsigned char i=0;
	unsigned char value;

	if (ds->lastsub == NULL)
		return;

	len = *(ds->lastsub + 1);
	ptr = ds->lastsub + 2;
	for (i=0; i < len; i++)
	{
		value = *ptr++;
		fprintf(stderr, "%s(%u) ", dhcp_str(value), value);
	}   
	fprintf(stderr, "\n");
}

/*
 * Build and send DHCP request.
 */
static int 
do_dhcp(char *packet, unsigned char *smac, long dstip)
{
	int len;
	int c;
	struct ip *ip = (struct ip *)(packet + LIBNET_ETH_H);
	struct _bootp *bp = (struct _bootp *)(packet + LIBNET_ETH_H + LIBNET_IP_H + LIBNET_UDP_H);

	memcpy(packet + ETH_ALEN, smac, ETH_ALEN);
	memcpy(bp->chaddr, smac, ETH_ALEN);

	len = LIBNET_ETH_H + LIBNET_IP_H + LIBNET_UDP_H + DHCP_MIN_OPT;
	ip->ip_len = htons(len - LIBNET_ETH_H);
	ip->ip_dst.s_addr = htonl(dstip);
	libnet_do_checksum(packet + LIBNET_ETH_H, IPPROTO_IP, LIBNET_IP_H);
	c = libnet_write_link_layer(opt.network, opt.device, packet, len);
	if (c != len)
		libnet_error(LIBNET_ERR_FATAL, "libnet_write_link_layer: %d bytes\n", c);

	return 0;
}

static void
init_vars(void)
{
	struct ip *ip;

	opt.ip_socket = init_pcap(opt.device, 1, "udp and dst port 68", NULL, NULL, &opt.dlt_len);
	opt.network = init_libnet(&opt.device, NULL);
	packet = (buf_packet + 2); /* IP header should be aligned */
	ip = (struct ip *)(packet + LIBNET_ETH_H);

	if (libnet_init_packet(MAX_PAYLOAD_SIZE, &lnet.packet) == -1)
		libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");

	dhcp_gen_packets(packet, LIBNET_UDP_H + DHCP_MIN_OPT, opt.src_ip, dsbuf, &ds);
}

static void
show_info()
{
	fprintf(stderr, "Device      : %s\n", opt.device);
	//fprintf(stderr, "srcMAC      : %s", val2mac(bmac.start_mac));
        //fprintf(stderr, "-%s\n", val2mac(bmac.end_mac));
        //fprintf(stderr, "dstMAC      : %s\n", val2mac(spfdstmac));
        fprintf(stderr, "srcIP       : %s\n", int_ntoa(opt.src_ip));
	fprintf(stderr, "DHCP Opts   : ");
	dhcp_print_lastsub(&ds);    /* print last suboptions */
}

static void
usage(void)
{
	fprintf(stderr, ""
"usage: dhcp [options] [target IP/Range] ...\n"
" 255.255.255.255 is used as default target.\n"
" -l <n>              Hosts in parallel (%d)\n"
/*" -s <IP>             source IP (%s)\n" */
" -v                  vebose\n"
" -m <mac>            source mac (random: %s)\n"
" -D <val1[,val2]>    DHCP option, 0=List DHCP options\n"
"", DFL_HOSTS_PARALLEL, val2mac(srcmac));

	exit(0);
}

static void
init_defaults(void)
{
	MAC_gen_pseudo(srcmac);
	opt.dst_ip = -1;  /* 255.255.255.255 */
	//opt.src_ip = 0;   /* 0.0.0.0 */
	init_dhcpset(&ds, dsbuf, DHCP_MIN_OPT);
	if (opt.hosts_parallel == 0)
		opt.hosts_parallel = DFL_HOSTS_PARALLEL;
}

static void
do_getopt(int argc, char *argv[])
{
	char *ptr;
	int c;
	int dhcp_set = 0;

	optind = 1;
	while ( (c = getopt(argc, argv, "+vhD:m:")) != -1)
	{
		switch (c)
		{
		case 'v':
			opt.flags |= FL_OPT_VERBOSE;
			break;
		case 'D':
			dhcp_set = 1;
			if (atoi(optarg) == 0)
			{
				list_dhcp();
				exit(0);
			}
			while ( (ptr = strchr(optarg, ',')) != NULL)
			{
				*ptr++ = '\0';
				dhcp_add_suboption(&ds, atoi(optarg));
				optarg = ptr;
			}
			if (*optarg != 0)  /* someone passed "1," */
				dhcp_add_suboption(&ds, atoi(optarg));
			break;
#if 0
		case 's':
			opt.src_ip = inet_addr(optarg);
			break;
#endif
		case 'm':
			opt.flags |= FL_OPT_SPOOFMAC;
			macstr2mac(srcmac, optarg);
			break;
		default:
			usage();
		}
	}

	if (!dhcp_set)
		dhcp_set_default(&ds);

	opt.argvlist = &argv[optind];
	opt.argc = argc - optind;
}

static void
dis_timeout(struct _state *state)
{
	switch (STATE_current(state))
	{
	case STATE_RESET:
		STATE_current(state) = STATE_DHCPI;
		do_dhcp(packet, srcmac, STATE_ip(state));
		break;
	case STATE_DHCPI:
		STATE_current(state) = STATE_DHCPII;
		do_dhcp(packet, srcmac, STATE_ip(state));
		break;
	case STATE_DHCPII:
		STATE_current(state) = STATE_DHCPIII;
		do_dhcp(packet, srcmac, STATE_ip(state));
		break;
	case STATE_DHCPIII:
		STATE_reset(state);
		break;
	default:
		fprintf(stderr, "Unknown state: %d\n", STATE_current(state));
		STATE_reset(state);
		break;
	}
}

static void
cb_filter(void)
{
	if (pcap_dispatch(opt.ip_socket, -1, (pcap_handler) dhcp_filter, NULL) < 0)
	{
		pcap_perror(opt.ip_socket, "pcap_dispatch");
		exit(-1);
	}
}

static void
bootp_print(struct ip *ip, struct _bootp *bp, int len)
{
	char *ptr;
	int c;
	unsigned char buf[2048];
	unsigned char dptype, dplen;

	printf("BOOTP reply from %s -> ", int_ntoa(ip->ip_src));
	printf("%s\n", int_ntoa(ip->ip_dst));
	printf("  Server      : %s\n", int_ntoa(bp->siaddr));
	printf("  Client      : %s\n", int_ntoa(bp->yiaddr));
	printf("  Relay Agent : %s\n", int_ntoa(bp->giaddr));
	printf("  ServerName  : %.*s\n", (int)sizeof bp->sname, bp->sname);
	printf("  BootFile    : %.*s\n", (int)sizeof bp->file, bp->file);
	printf("  MAC         : %s\n", val2mac(bp->chaddr));

	ptr = bp->options;
	c = 4;  /* magic cookie */
	while (c + 2 < len)
	{
		if ( (dptype = *(ptr + c++)) == DHCP_END)
			break;
		if ( (dplen = *(ptr + c)) > len - c)
			break;

		dhcp_val2str(buf, sizeof buf, dptype, dplen, ptr + c + 1);
		printf("  %s\n", buf);
		c += *(ptr + c) + 1;
	}
}

static void
dhcp_filter(unsigned char *u, struct pcap_pkthdr *p, unsigned char *packet)
{
	char buf[2048];
	struct ip ip;
	struct udphdr *udp = (struct udphdr *)buf;
	unsigned short options;
	size_t len;  /* udp header + data */
	struct _bootp *bp = (struct _bootp *)(buf + 8);

	/* 312 + 20 + 8 */
	if (p->caplen < (opt.dlt_len + 20 + 8))
		return;	
	memcpy(&ip, packet + opt.dlt_len, sizeof ip);
	if ( vrfy_ip(&ip, p->caplen - opt.dlt_len, &options) != 0)
		return;

	len = p->caplen - opt.dlt_len - 20 - options;
	if (sizeof buf < len)
		len = sizeof buf;
	memcpy(buf, packet + opt.dlt_len + 20 + options, len);

	if (p->caplen < opt.dlt_len + 20 + options)
		return;

	if (ip.ip_p != IPPROTO_UDP)
		return;

	if (vrfy_udp(udp, len) != 0)
		return;

	if (udp->uh_dport != htons(68))
		return;

	if (bp->op != BOOTP_REPLY)
		return;

	if (len > ntohs(udp->uh_ulen))
		len = ntohs(udp->uh_ulen);

	if (len < sizeof(struct _bootp) + 8)
		return;  /* Empty BOOTP message */

	bootp_print(&ip, bp, len - 8 - sizeof(struct _bootp));

	exit(0); /* exit after first answer we got */
}

int
dhcp_main(int argc, char *argv[])
{
	struct _ipranges ipr;
	struct _state state;
	int ret;

	memset(buf_packet, 0, sizeof buf_packet);

	init_defaults();
	do_getopt(argc, argv);
	init_vars();

	/*
	 * Use default broadcast if no IP is given.
	 */
	if (opt.argc == 0)
	{
		opt.argvlist--;
		opt.argvlist[0] = "255.255.255.255";
		opt.argc++;
	}
	IP_init(&ipr, opt.argvlist,  (opt.flags & FL_OPT_SPREADMODE)?IPR_MODE_SPREAD:0);

	if (opt.flags & FL_OPT_VERBOSE)
		show_info();

        if (!SQ_init(&opt.sq, opt.hosts_parallel, sizeof(struct _state), pcap_fileno(opt.ip_socket), dis_timeout, cb_filter))
	{
		fprintf(stderr, "Failed to init states: %s\n", strerror(errno));
		exit(-1); /* Out of Memory */
	}

	/* Set MAC here */
	memset(&state, 0, sizeof state);

	while (1)
	{
		IP_next(&ipr);
		if (IP_current(&ipr))
                {
                        STATE_ip(&state) = IP_current(&ipr);
                        ret = STATE_wait(&opt.sq, &state);
                } else  
			ret = STATE_wait(&opt.sq, NULL);

		if (ret != 0)
			break;
	}

	return 0;
}

