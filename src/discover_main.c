/*
 * $Id: discover_main.c,v 1.8 2003/05/25 18:19:16 skyper Exp $
 */

#include <sys/time.h>
#include <time.h>
#include <pcap.h>
#include <libnet.h>
#include "default.h"
#include "thcrut.h"
#include "state.h"
#include "range.h"
#include "thcrut_pcap.h"
#include "thcrut_sig.h"
#include "network_raw.h"
#include "nmap_compat.h"
#include "packets.h"
#include "discover_dispatch.h"
#include "network.h"
#include "thcrut_libnet.h"

extern struct _opt opt;
extern char ip_tcp_sync[];

struct sockaddr_in ip_tcp_sync_addr;
int rawsox;

#define DFL_HOSTS_PARALLEL	(5000)

void
cb_filter(void)
{
	if (pcap_dispatch(opt.ip_socket, -1 /* 1024 */, (pcap_handler) scanner_filter, NULL) < 0)
	{
		pcap_perror(opt.ip_socket, "pcap_dispatch");
		exit(-1);
	}
}

#if 0
void
cb_timeout(struct _state *state)
{
	DEBUGF(" CALLBACK\n");
	STATE_current(state) = 1;
	dis_timeout(state);
	return;
}
#endif

static void
launch(struct _ipranges *ipr)
{
	char buf[opt.sq.item_size];
	struct _state *state = (struct _state *)buf;
	int ret;

	memset(buf, 0, opt.sq.item_size);

	while (1)
	{
		IP_next(ipr);
//		if (IP_current(ipr) && ((IP_current(ipr) == opt.net) || (IP_current(ipr) == opt.bcast)))
//				continue;

		if (IP_current(ipr))
		{
			STATE_ip(state) = IP_current(ipr);
			ret = STATE_wait(&opt.sq, state);
		} else
			ret = STATE_wait(&opt.sq, NULL);

		if (ret != 0)
			break;
	}
}


/*
 * init_defaults is called before getopt()
 */
static void
init_defaults(void)
{
	opt.flags |= FL_OPT_HOSTDISCOVERY;
	if (opt.hosts_parallel == 0)
		opt.hosts_parallel = DFL_HOSTS_PARALLEL;
}

/*
 * Return 1 if NMAP file could not be loaded.
 * Return 2 if thcrut-os filge could not be loaded
 * Return 3 if both failed.
 * Return 0 on success.
 */
#define MAX_DIR_LEN       (1024)
static int
config_fp_load(char *buf, char *dir)
{
	char err = 0;

	snprintf(buf, MAX_DIR_LEN, "%s/nmap-os-fingerprints", dir);
	if (NMAP_load_fp(&opt.osfp, buf) != 0)
		return 1;
	snprintf(buf, MAX_DIR_LEN, "%s/thcrut-os-fingerprints", dir);
	if (FP_TS_load(&opt.fpts, buf) != 0)
		return 2;

	return err;
}

/*
 * Get source ip of primary interface.
 * I dont know any other portable way. The famous binding a UDP socket
 * and doing the getsockname() is broken on OpenBSD 2.8(>?) if no
 * default gateway is assigned (returns 127.0.0.1 :>).
 *
 * Return 0 if not found/error. (This way will it be set later by
 * the tcp-send-function. This can happen if 'any' device is used).
 */
static void
getmyip_by_device(void)
{
	struct libnet_link_int *network;

	network = init_libnet(&opt.device, &opt.src_ip);
	if (network)
		fini_libnet(network);
}

/*
 * Init vars is called after getopt.
 */
static void
init_vars(void)
{
	int i = 1* 1024 * 1024; /* Is reduced to max. anyway */
	size_t size;
	char buf[MAX_DIR_LEN];
	char *ptr;
	struct stat sbuf;

	/* This goes after getopt */
	if (opt.flags & FL_OPT_HOSTDISCOVERY)
	{
		if ((ptr = getenv("THCRUTDIR")))
		{
			if (config_fp_load(buf, ptr) != 0)
			{
				fprintf(stderr, "Failed to load \"%s\": %s\n", buf, strerror(errno));
				exit(-1);
			}
		} else if (config_fp_load(buf, THCRUT_DATADIR) != 0) {
			if (config_fp_load(buf, ".") != 0)
			{
				fprintf(stderr, "Failed to load \"%s\": %s\n", buf, strerror(errno));
				exit(-1);
			}
		} else if (stat("./thcrut-os-fingerprints", &sbuf) == 0) {
			fprintf(stderr, "WARNING: ./thcrut-os-fingerprints exist. Using config files from "THCRUT_DATADIR" for security reasons.\nset THCRUTDIR=. to overwrite.\n");
		}
	}
	//FP_TS_dump(&opt.fpts);

	//rawsox = libnet_open_raw_sock(IPPROTO_RAW);
	rawsox = net_sock_raw();
	if (rawsox < 0)
	{
		fprintf(stderr, "socket: %s\n", strerror(errno));
		exit(-1);
	}

	/* FIXME: Filtering is acutually done in userland (on most
	 * systems. Our own filter might be much faster....
	 * (pcap_dispatch() filters and calls the dispatcher on match.
	 * The dispatcher has to parse anyway....so why not filter there?
	 */
	/* init pcap */
	snprintf(buf, sizeof buf, "icmp[4:2] = %u or ((udp or tcp) and (dst port %u or dst port %u or dst port %u))", htons((unsigned short)getpid()), opt.src_port, opt.src_port + 1, opt.src_port + 2);
	//DEBUGF("Filter: \"%s\"\n", buf);
	opt.ip_socket = init_pcap(opt.device, 0, buf, &opt.net, &opt.bcast, &opt.dlt_len);

	if (opt.flags & FL_OPT_FP)
	{
		size = sizeof(struct _state_fp);
		/*
		 * Reserve 2 bits for TCP or UDP state (Open, closed, Unknown)
		 * Reserve some bytes if we perform banner matching (this sucks memory).
		 */
		opt.fpts.cat[FP_CAT_NVT].size = opt.fpts.cat[FP_CAT_NVT].n_tests * FP_NTEST_SZ;
		opt.fpts.cat[FP_CAT_SNMP].size = opt.fpts.cat[FP_CAT_SNMP].n_tests * FP_STEST_SZ;
		opt.fpts.cat[FP_CAT_WWW].size = opt.fpts.cat[FP_CAT_WWW].n_tests * FP_WTEST_SZ; /* 64 bytes for every WWW banner */
		opt.fpts.cat[FP_CAT_BANNER].size = opt.fpts.cat[FP_CAT_BANNER].n_tests * FP_BTEST_SZ;
		opt.fpts.cat[FP_CAT_TCP].size = opt.fpts.cat[FP_CAT_TCP].n_tests?opt.fpts.cat[FP_CAT_TCP].n_tests / 4 + 1:0;
		opt.fpts.cat[FP_CAT_UDP].size = opt.fpts.cat[FP_CAT_UDP].n_tests?opt.fpts.cat[FP_CAT_UDP].n_tests  / 4 + 1:0;

		for (i = 0; i < sizeof opt.fpts.cat / sizeof *opt.fpts.cat; i++)
			size += opt.fpts.cat[i].size;

		opt.fpts.ofs_test_tcp = 0;
		opt.fpts.ofs_test_udp = opt.fpts.ofs_test_tcp + opt.fpts.cat[FP_CAT_TCP].size;
		opt.fpts.ofs_test_banner = opt.fpts.ofs_test_udp + opt.fpts.cat[FP_CAT_UDP].size;
		opt.fpts.ofs_test_www = opt.fpts.ofs_test_banner + opt.fpts.cat[FP_CAT_BANNER].size;
		opt.fpts.ofs_test_snmp = opt.fpts.ofs_test_www + opt.fpts.cat[FP_CAT_WWW].size;
		opt.fpts.ofs_test_nvt = opt.fpts.ofs_test_snmp + opt.fpts.cat[FP_CAT_SNMP].size;
	} else {
		size = sizeof(struct _state_dis);
	}

	/*
	 * We need the src ip to calculate the correct TCP checksum.
	 * This wont work on the 'any' device.
	 */
	getmyip_by_device();
	scanner_gen_packets();

	//DEBUGF("size %d %d\n", sizeof(struct _state_fp), size);
	if (!SQ_init(&opt.sq, opt.hosts_parallel, size, pcap_fileno(opt.ip_socket), dis_timeout, cb_filter))
	{
		fprintf(stderr, "Failed to init states: %s\n", strerror(errno));
		exit(-1); /* Out of Memory */
	}
}

static void
usage(char *str)
{
	if (str)
		fprintf(stderr, "%s\n", str);

	printf(""
"usage: discover [options] [IP range] ...\n"
"             with IP range of the form a.b.c.d-x.y.z.w\n"
" -d          Don't do host discovery (tcp-sync ping, ...)\n"
" -O          With OS Fingerprinting\n"
" -v          verbose output (fingerprint stamps)\n"
" -l <n>      Hosts in parallel (default: %d)\n"
"", DFL_HOSTS_PARALLEL);
	if (str)
		exit(-1);
	exit(0);
}

/*
 * Set source IP, rate limit, ...
 */
static void
do_getopt(int argc, char *argv[])
{
	int c;

	/*
	 * We call getopt() for a second time.
	 * Set optind to 0 to reinit getopt() variables.
	 * We must thus start at index 0 and must
	 * remove the programs name.
	 *
	 * Linux inits (?) but always starts at 1.
	 */
	optind = 1;
	if (argc == 1)
		usage("Arguement required");

	while ((c = getopt(argc, argv, "+Obdhvl:")) != -1)
	{
		switch (c)
		{
		case 'l':
			opt.hosts_parallel = atoi(optarg);
			if (opt.hosts_parallel <= 0)
				opt.hosts_parallel = DFL_HOSTS_PARALLEL;
			break;
		case 'O':
			opt.flags |= FL_OPT_FP;
			break;
		case 'd':
			opt.flags &= ~FL_OPT_HOSTDISCOVERY;
			break;
		case 'b': /* Binary output */
			opt.flags |= FL_OPT_BINOUT;
			break;
		case 'v':
			opt.flags |= FL_OPT_VERBOSE;
			break;
		case 'h':
			usage(NULL);
			break;
		default:
			usage("Wrong option");
		}
	}

	if ((opt.flags & FL_OPT_FP) && (opt.hosts_parallel > 1000))
	{
		if (opt.hosts_parallel != DFL_HOSTS_PARALLEL)
		{
			fprintf(stderr, "Operating System Fingerprinting limited to 1000 hosts in parallel (fixed).\n");
			opt.hosts_parallel = 1000;
		} else
			opt.hosts_parallel = 400; /* Default for OSFP */
	}

	opt.argvlist = &argv[optind];
	opt.argc = argc - optind;
}

#if 0
static void
test_filter(unsigned char *u, struct pcap_pkthdr *p, unsigned char *packet)
{
	static int i;
	struct pcap_stat ps;

	return;
	i++;
	if (i++ <= 1)
		return;
	if (thcrut_pcap_stats(opt.ip_socket, &ps) == 0)
		fprintf(stderr, "TEST %u packets received by filter, %u packets dropped by kernel\n", ps.ps_recv, ps.ps_drop);
	i = 0;
}

void
testme(void)
{
	char buf[4096];

	snprintf(buf, sizeof buf, "icmp[4:2] = %d or ((udp or tcp) and (dst port %d or dst port %d or dst port %d))", htons(getpid()), opt.src_port, opt.src_port + 1, opt.src_port + 2);
	//DEBUGF("Filter: \"%s\"\n", buf);
	opt.ip_socket = init_pcap(opt.device, 0, /*buf*/ NULL, &opt.net, &opt.bcast, &opt.dlt_len);

	while (1)
	{
		if (pcap_dispatch(opt.ip_socket, 0, (pcap_handler) test_filter, NULL) < 0)
			exit(-1);
	}
}

void
sigchld(int sig)
{
#if 1
	struct pcap_stat ps;

	if (thcrut_pcap_stats(opt.ip_socket, &ps) == 0)
		fprintf(stderr, "PARENT %u packets received by filter, %u packets dropped by kernel\n", ps.ps_recv, ps.ps_drop);
#endif
	_exit(0);
}
#endif

#if 1
void
testme(void)
{
	int ret;
	struct ip *ip = (struct ip *)(ip_tcp_sync);
	int n = 0;

	ip->ip_dst.s_addr = inet_addr("10.1.23.1");

	while (n < 100000)
	{
		ret = net_send(rawsox, ip_tcp_sync, 40);
		n++;
		if (ret <= 0)
			break;
	}
	DEBUGF("ret = %d after %d packets\n", ret, n);
	exit(0);
}
#endif
void
testsend(int myip)
{
	struct ip *ip = (struct ip *)(ip_tcp_sync);
	
	ip->ip_dst.s_addr = htonl(myip);
	net_send(rawsox, ip_tcp_sync, 40);
}


int
scanner_main(int argc, char *argv[])
{
	struct pcap_stat ps;

	init_defaults();
	do_getopt(argc, argv);
	init_vars();

	signal(SIGPIPE, SIG_IGN);  /* Have to ignore this */
	IP_init(&opt.ipr, opt.argvlist,  (opt.flags & FL_OPT_SPREADMODE)?IPR_MODE_SPREAD:0);
	//testme();
#if 0
	DEBUGF("Total ip's: %u\n", opt.ipr.total);
	while (1)
	{
		IP_next(&opt.ipr);
		if (!IP_current(&opt.ipr))
		{
			DEBUGF("current is 0\n");
			break;
		}
		//testsend(IP_current(&ipr));
		DEBUGF("%s\n", int_ntoa(IP_current(&opt.ipr)));
	}
	return 0;
#endif
	launch(&opt.ipr);

	/* This information is unreliable. Drops much more! */
	if (thcrut_pcap_stats(opt.ip_socket, &ps) == 0)
		fprintf(stderr, "%u packets received by filter, %u packets dropped by kernel\n", ps.ps_recv, ps.ps_drop);

	return 0;
}

