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
#include "thc-rut.h"
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

static struct _dhcpset ds;
static uint8_t dsbuf[1024];
static uint8_t payload[1024];
static uint8_t srcmac[ETH_ALEN];

static libnet_ptag_t ln_udp;
static libnet_ptag_t ln_ip;
static libnet_ptag_t ln_eth;

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
do_dhcp(uint32_t dstip)
{
	int c;
	struct _bootp *bp = (struct _bootp *)(payload);

	/* For every request we may pick a random source mac */
	if (opt.flags & FL_OPT_RANDMAC)
		MAC_gen_pseudo(srcmac);

	memcpy(bp->chaddr, srcmac, ETH_ALEN);

	ln_udp = libnet_build_udp(68,
		67,
		LIBNET_UDP_H + sizeof (struct _bootp) + ds.lsize,
		0,
		payload,
		sizeof (struct _bootp) + ds.lsize,
		opt.ln_ctx,
		ln_udp);

	ln_ip = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + sizeof (struct _bootp) + ds.lsize,
		0,		/* TOS */
		opt.ip_id,	/* IP ID */
		0,		/* frags */
		128, 		/* TTL */
		IPPROTO_UDP,
		0,
		opt.src_ip,
		dstip,
		NULL,
		0,
		opt.ln_ctx,
		ln_ip);

	ln_eth = libnet_build_ethernet(opt.dst_mac,
		srcmac,
		ETHERTYPE_IP,
		NULL, 0, opt.ln_ctx, ln_eth);
	
	c = libnet_write(opt.ln_ctx);

	if (c == -1)
		ERREXIT("libnet_write() = %d: %s\n", c, libnet_geterror(opt.ln_ctx));

	return 0;
}

static void
init_vars(void)
{
	opt.ip_socket = init_pcap(opt.device, 1, "udp and dst port 68", NULL, NULL, &opt.dlt_len);
	opt.ln_ctx = init_libnet(opt.device, &opt.src_ip);

	struct libnet_ether_addr *hw;
	hw = libnet_get_hwaddr(opt.ln_ctx);
	if (hw == NULL)
		ERREXIT("libnet_get_hewaddr: %s\n", libnet_geterror(opt.ln_ctx));

	/* Random mac: Randomize last 4 octets. */
	if ((opt.flags & FL_OPT_RANDMAC) || (!(opt.flags & FL_OPT_SPOOFMAC)))
		memcpy(srcmac, hw->ether_addr_octet, ETH_ALEN);

	dhcp_gen_packets(payload, opt.src_ip, dsbuf, &ds);
	//HEXDUMP(payload, sizeof (struct _bootp));
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
" -m <mac>            source mac (interace's default or -m 0 for random)\n"
" -d <mac>            destination mac (default: broadcast)\n"
" -D <val1[,val2]>    DHCP option, 0=List DHCP options, all=ALL (!)\n"
"", DFL_HOSTS_PARALLEL);

	exit(0);
}

static void
init_defaults(void)
{
	//MAC_gen_pseudo(srcmac);
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
	while ( (c = getopt(argc, argv, "+vhd:D:m:")) != -1)
	{
		switch (c)
		{
		case 'v':
			opt.flags |= FL_OPT_VERBOSE;
			break;
		case 'D':
			if (strncmp(optarg, "all", 3) == 0)
			{
				dhcp_set = 1;
				break;
			}
			if (atoi(optarg) == 0)
			{
				list_dhcp();
				exit(0);
			}
			dhcp_set = 2;
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
		case 'd':
			macstr2mac(opt.dst_mac, optarg);
			break;
		case 'm':
			opt.flags |= FL_OPT_SPOOFMAC;
			macstr2mac(srcmac, optarg);
			if (memcmp(srcmac, ETHZCAST, 6) == 0)
				opt.flags |= FL_OPT_RANDMAC;
			break;
		default:
			usage();
		}
	}

	if (dhcp_set == 0)
		dhcp_set_default(&ds);
	if (dhcp_set == 1)
		dhcp_set_all(&ds);

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
		do_dhcp(STATE_ip(state));
		break;
	case STATE_DHCPI:
		STATE_current(state) = STATE_DHCPII;
		do_dhcp(STATE_ip(state));
		break;
	case STATE_DHCPII:
		STATE_current(state) = STATE_DHCPIII;
		do_dhcp(STATE_ip(state));
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
	uint8_t *ptr;
	int c;
	char buf[2048];
	unsigned char dptype, dplen;

	printf("BOOTP reply from %s -> ", int_ntoa(ip->ip_src.s_addr));
	printf("%s\n", int_ntoa(ip->ip_dst.s_addr));
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

	memset(payload, 0, sizeof payload);

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
                        STATE_ip(&state) = htonl(IP_current(&ipr));
                        ret = STATE_wait(&opt.sq, &state);
                } else  
			ret = STATE_wait(&opt.sq, NULL);

		if (ret != 0)
			break;
	}

	return 0;
}

