/*
 * $Id:$
 *
 * Pretty interesting which OS answers for arp request for
 * 127.0.0.1, 0.0.0.0 or gives replies about MAC from other
 * interfaces (linux for example).
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
#include "macvendor.h"
#include "thc-rut.h"
#include "range.h"
#include "packets.h"
#include "network.h"
#include "network_raw.h"
#include "thcrut_libnet.h"
#include "thcrut_pcap.h"

#define STATE_RESET	(0)
#define STATE_ARPI	(1)
#define STATE_ARPII	(2)
#define STATE_ARPIII	(3)

#define DFL_HOSTS_PARALLEL	(100)

extern struct _opt opt;
static void arp_filter(unsigned char *u, struct pcap_pkthdr *p, unsigned char *packet);
static void do_arp();

static libnet_ptag_t ln_arp;
static libnet_ptag_t ln_eth;
static uint8_t srcmac[ETH_ALEN];

static void
init_vars(void)
{
	char buf[1024];
	char *ptr;
	struct stat sbuf;
	char err_buf[LIBNET_ERRBUF_SIZE];
	struct libnet_ether_addr *hw;

	opt.ip_socket = init_pcap(opt.device, 1, "arp[6:2] = 2", NULL, NULL, &opt.dlt_len);
	/*
	 * Only listen to replies.
	 */
	if (!(opt.flags & FL_OPT_SPOOFMAC))
	{
		//hw = libnet_get_hwaddr(opt.network, opt.device, err_buf);
		hw = libnet_get_hwaddr(opt.ln_ctx);
		if (!hw)
		{
			fprintf(stderr, "libnet_get_hwaddr: %s\n", err_buf);
			exit(-1);
		}
		memcpy(srcmac, hw->ether_addr_octet, ETH_ALEN);
	}

	arp_gen_packets(opt.src_ip);

	/*
	 * Try to load mac vendor DB. Ignore if we fail.
	 */
	if ( (ptr = getenv("THCRUTDIR")))
	{
		snprintf(buf, sizeof buf, "%s/manuf", ptr);
		readvendornames(buf);
	} else {
		snprintf(buf, sizeof buf, "%s/manuf", THCRUT_DATADIR);
		if (readvendornames(buf) != 0)
		{
			if (readvendornames("./manuf") != 0)
				fprintf(stderr, "Load ./manuf: %s\n", strerror(errno));
		} else if (stat("./manuf", &sbuf) == 0) {
			fprintf(stderr, "WARNING: ./manuf exist. Using config file from "THCRUT_DATADIR" for security reasons.\nset THCRUTDIR=. to overwrite.\n");
		}
	}
}

static void
usage(void)
{
	fprintf(stderr, ""
"usage: arp [options] [IP] ...\n"
" -l <n>              Hosts in parallel (%d)\n"
" -m <mac>            source MAC (source interface)\n"
"", DFL_HOSTS_PARALLEL);

	exit(0);
}

/*
 * Init libnet here because we want to display the correct IP
 */
static void
init_defaults(void)
{
	opt.ln_ctx = init_libnet(opt.device /*, &opt.src_ip*/);
	if (opt.hosts_parallel == 0)
		opt.hosts_parallel = DFL_HOSTS_PARALLEL;
}

static void
do_getopt(int argc, char *argv[])
{
	int c;

	optind = 1;
	while ( (c = getopt(argc, argv, "+hl:m:")) != -1)
	{
		switch (c)
		{
		case 'l':
			opt.hosts_parallel = atoi(optarg);
			break;
		case 'm':
			macstr2mac(srcmac, optarg);
			opt.flags |= FL_OPT_SPOOFMAC;
			break;
		default:
			usage();
		}
	}

	opt.argvlist = &argv[optind];
	opt.argc = argc - optind;

	if (opt.argc <= 0)
		usage();
}

/*
 * Send arp request
 */
static void
do_arp(uint32_t ip)
{
	//struct ETH_arp *eth_arp = (struct ETH_arp *)(packet + LIBNET_ETH_H);
	int c;

	ip = htonl(ip);

	ln_arp = libnet_build_arp(ARPHRD_ETHER,
			ETHERTYPE_IP,
			6, 4, ARPOP_REQUEST,
			srcmac /*ETHZCAST*/,
			(uint8_t *)&opt.src_ip,
			ETHBCAST,
			(uint8_t *)&ip, 
			NULL, 0, opt.ln_ctx, ln_arp);

	ln_eth = libnet_build_ethernet(ETHBCAST,
			srcmac /*ETHZCAST*/,
			ETHERTYPE_ARP,
			NULL, 0, opt.ln_ctx, ln_eth);

	c = libnet_write(opt.ln_ctx);
	if (c != LIBNET_ETH_H + LIBNET_ARP_H)
	{
		ERREXIT("libnet_write() = %d, %s\n", c, libnet_geterror(opt.ln_ctx));
	}
}

static void
dis_timeout(struct _state *state)
{
	switch (STATE_current(state))
	{
	case STATE_RESET:
		STATE_current(state) = STATE_ARPI;
		do_arp(STATE_ip(state));
		break;
	case STATE_ARPI:
		STATE_current(state) = STATE_ARPII;
		do_arp(STATE_ip(state));
		break;
	case STATE_ARPII:
		STATE_current(state) = STATE_ARPIII;
		do_arp(STATE_ip(state));
		break;
	case STATE_ARPIII:
		STATE_reset(state);
		break;
	default:
		fprintf(stderr, "%s:%d Unknown state %d\n", __func__, __LINE__, STATE_current(state));
		STATE_reset(state);
		break;
	}
}

static void
cb_filter(void)
{
	if (pcap_dispatch(opt.ip_socket, -1, (pcap_handler)arp_filter, NULL) < 0)
	{
		pcap_perror(opt.ip_socket, "pcap_dispatch");
		exit(-1);
	}
}

static void
arp_filter(unsigned char *u, struct pcap_pkthdr *p, unsigned char *packet)
{
	struct ETH_arp *arp = (struct ETH_arp *)(packet + LIBNET_ETH_H);
	struct _state *state;
	long l;
	char *ptr;

	if (p->caplen < LIBNET_ETH_H + sizeof *arp)
		return;
	memcpy(&l, arp->ar_sip, 4);

	if (!(state = STATE_by_ip(&opt.sq, ntohl(l))))
		return;

	ptr = mac2vendor(arp->ar_sha);
	/*
	 * 16 bytes for IP, 1 byte for space, 17 for mac + 1 space = 35
	 * 80 - 35 = 45.
	 */
	if (!ptr)
		printf("%-16s %.45s\n", int_ntoa(l), val2mac(arp->ar_sha));
	else
		printf("%-16s %s %.45s\n", int_ntoa(l), val2mac(arp->ar_sha), ptr);

	STATE_reset(state);
}


int
arp_main(int argc, char *argv[])
{
	struct _state state;
	struct pcap_stat ps;
	int ret;

	init_defaults();
	do_getopt(argc, argv);
	init_vars();

	IP_init(&opt.ipr, opt.argvlist, (opt.flags & FL_OPT_SPREADMODE)?IPR_MODE_SPREAD:0);

	if (!SQ_init(&opt.sq, opt.hosts_parallel, sizeof(struct _state), pcap_fileno(opt.ip_socket), dis_timeout, cb_filter))
	{
		fprintf(stderr, "Failed to init states: %s\n", strerror(errno));
		exit(-1);
	}

	memset(&state, 0, sizeof state);
	while (1)
	{
		IP_next(&opt.ipr);
		if (IP_current(&opt.ipr))
		{
			STATE_ip(&state) = IP_current(&opt.ipr);
			ret = STATE_wait(&opt.sq, &state);
		} else
			ret = STATE_wait(&opt.sq, NULL);

		if (ret != 0)
			break;
	}

	if (thcrut_pcap_stats(opt.ip_socket, &ps) == 0)
		fprintf(stderr, "%u packets received by filter, %u packets dropped by kernel\n", ps.ps_recv, ps.ps_drop);

	return 0;
}

