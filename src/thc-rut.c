/*
 * its 2001-05-03, this is quick _dirty_ code.
 * gamma called me..doiong some wvlan-riding now..
 * wrote this lame stuff to brute force BOOTP replies
 * on wlan access points with mac-authentification.
 * sends BOOTP requests with different macs...thats all.
 *
 *
 * anonymous@segfault.net
 * err..let me fix the bugs later. ideas:
 * - ARP whohas does not work with switched network and
 *   PortSecurity enabled. send out some arp-have first!
 *   Its nice to use src mac ff:ff:ff:ff:ff:ff...works for the 
 *   switch but not OSes answer on it. only ONE (the first?) 
 *   Interface of VMWAREs NIC answers (hahahahah)
 *   Another nice idea to determine the OS of a host...
 * - multicast
 * - rarp RFC 903, skip it, bootp is newer...and dhcp also.
 * - ?! what else can be used if you dont know the network-address 
 *   and access is only granted from specific (unknown) mac's ?
 *   With BOOTP we only need to brute force the src-mac..hmm..ok.
 * + icmp address mask request ..FIXME: dst-mac if ff:ff:ff:ff:ff:ff wont work.
 * + ping 255.255.255.255
 * + request all arp's on the lan
 * - Resource Location Protocol RFC 887
 * + DHCP 1541 + 1497 (optoins) + 1533 + 1542 (clarification + extensions
 *   for bootstrap protocol)
 *   and RFC2131
 * - BOOTP RFC 951
 * - ICMP-router discovery RFC 1256 (need to verify; 224.0.0.[12]) 
 * - DRARP by sun ? MIT ? ("Dynamic Reverse Address Resolution Protocol")
 * - BOOTPARAMS by sun
 * + mac-vendor name
 * - statefull / retransmit packet if no response...
 * + limit packets/second
 * - SOCK_RAW for ppl on ppp-dialups and local cable modem hacking [no ethernet]
 *   -> arpg wont work and arp on an entire network also not.anyway..icmp + dhcp
 * -------- info ---------
 * 00:40:96:47xxxx cisco access point
 * 00:02:2D:08:2A:54 lucent wvlan
 * 00:02:2D:04:C7:18 lucent wvlan
 * 00:02:2D:02:91:73 lucent wvlan
 * 00:02:2D:0E:99:52 lucent wvlan orinoco silver
 * 00:60:1D:23:21:9B lucent wvlan
 * 00:60:1d:21:9f:32 lucent wvlan
 * 08:00:0E AT&T Wavelan (standard) & DEC RpamAbout
 * 08:00:6A AT&T Wavelan (alternate)
 * 00:00:E1 Hitachi Wavelan
 * 00:60:1D Lucent Wavelan
 * The networkname of a rg1000 are always the last 3 digits of the AP-mac
 * (without the ':' signs, rg1000 by lucent)
 *
 * problems:
 * - we dont know the destination mac . we use ff:ff:ff:ff:ff:ff: in all cases
 *   ..this most often works for icmp (except for windows2k)
 *
 * thnx to scut for dcd_icmp.h and the bscan development team :]
 * thnx to oxigen for bootp samples late late in the night.
 *
 * TODO:
 * - implement a dummy mode for stupid users that just discovers everything
 *   on the local network.
 */

#include "default.h"
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <sys/types.h>
#ifdef HAVE_CONFIG_H
# if HAVE_SYS_WAIT_H
#  include <sys/wait.h>
# endif
# ifndef WEXITSTATUS
#  define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
# endif
# ifndef WIFEXITED
#  define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
# endif
#else
# include <sys/wait.h>
#endif
#include <libnet.h>
#include "thc-rut.h"
#include "network_raw.h"
#include "dcd_icmp.h"
#include "arpg.h"
#include "dhcp.h"
#include "macvendor.h"
#include "schedule.h"
#include "range.h"
#include "state.h"
#include "thcrut_sig.h"
#include "discover_main.h"
#include "dhcp_main.h"
#include "arp_main.h"
#include "icmp_main.h"
#include "network.h"
#include "fp.h"
#include "tty.h"
#include "thcrut_pcap.h"

#define DFL_WMEM_MAX	(1 * 1024 * 1024)

u_char spfdstmac[ETH_ALEN];
struct _spfip srcip;
struct _opt opt;
struct _lnet lnet;

void fini_libnet();

static unsigned long time_start;

void
init_vars()
{
	struct timeval tv;
	FILE *fp;
	char buf[128];

	time_start = (unsigned long)time(NULL);
	gettimeofday(&tv, NULL);
	memset(lnet.payload, 0, MAX_PAYLOAD_SIZE);
	opt.device = NULL;
	opt.dlt_len = ETHDLTLEN;
	opt.flags = 0;
	opt.flags |= FL_OPT_SPREADMODE;
	opt.hosts_parallel = 0;

	/* vendor: lucent oricion 2000 */
	memcpy(spfdstmac, ETHBCAST, ETH_ALEN);
	srcip.addr = 0;
	srand(time(NULL));   /* PRNG, we only require weak random */

	memcpy(opt.dst_mac, ETHBCAST, sizeof opt.dst_mac);

	signal_parent_init();

	/*
	 * Linux specific, set send buffer size
	 */
	fp = fopen("/proc/sys/net/core/wmem_max", "w+");
	if (fp)
	{
		if (fgets(buf, sizeof buf, fp) == NULL)
			ERREXIT("open(/proc/...wmem_max) = NULL\n");
		if (atoi(buf) < DFL_WMEM_MAX)
		{
			fprintf(stderr, "Setting system wide send buffer limit to %d bytes\n", DFL_WMEM_MAX);
			fseek(fp, 0L, SEEK_SET);
			fprintf(fp, "%d\n", DFL_WMEM_MAX);
		}
		fclose(fp);
	}

        /*
	 * Some statefull firewalls ipf are buggy:
	 * SYN passes, SYN|ACK anser passes,
	 * RST passes
	 * NEW SYN with same values does _NOT_ pass anymore.
	 * That's why we try to use a different port and let the
	 * ipf state timeout (should be time'ed out after 32k seconds)
	 * We reserve a new block of 8 source ports every 1/8 seconds which
	 * have not been used by the scanner during the last 512 seconds
	 * (most states timeout after 360).
	 */
        opt.src_port = (((tv.tv_sec & 0x1ff) << 3)+ (tv.tv_usec & 0x7))*8 + 1024;
	opt.ip_id = (uint16_t)(getpid() & 0xffff);
	opt.ic_id = (uint16_t)(getpid() & 0xffff);
}

void
die(int code, char *fmt, ...)
{
	va_list ap;
	char buf[1024];

	if (fmt != NULL)
	{
		va_start(ap, fmt);
		vsnprintf (buf, sizeof(buf)-1, fmt, ap);
		va_end(ap);	
		fprintf(stderr, "ERROR: %s\n", buf);
	}

	if (opt.childpid)
		kill(opt.childpid, SIGTERM);

	fini_libnet();

	exit(code);
}

void
usage (int code, char *str)
{
	if (str != NULL)
		fprintf(stderr, "%s\n", str);

	fprintf(stderr, 
"Version: "VERSION"\n"
"Usage: thc-rut [ options ] [ command ] [ command-options-and-arguments ]\n"
//[Types] [Options] [[macX[-macY]:]ipA[-ipB]] ...\n"
"\n"
"Commands:\n"
" discover        Host discovery and OS fingerprinting\n"
//" scan            Port scanner (TCP)\n"
" icmp            ICMP discovery\n"
" dhcp            DHCP discovery\n"
" arp             ARP discovery\n"
//" sniff           tcpdump\n"
"\n"
"Options:\n"
" -i <interface>  Network interface [first found]\n"
" -l <n>          Hosts in parallel\n"
/* NOTE: not all modules support spoofing. */
" -s <IP>         Source ip of a network device (eth0, eth0:0, ..)\n"
" -S              Sequential ip range mode [default: spread mode]\n"
" -F              Infinite Loop. Repeat forever.\n"
"Use -l 100 on LAN and -l 5000 otherwise.\n"
"Try thcrut [ command ] -h for command specific options.\n"
"\n"
"Example:\n"
"# thc-rut arp\n"
"# thc-rut icmp -h\n"
"# thc-rut icmp -T 151.101.121.1-151.101.121.254\n"
"# thc-rut dhcp\n"
"# thc-rut discover -h\n"
"# thc-rut discover -O 192.168.0.1-192.168.255.254\n"
	);

	exit(code);
}


int
do_getopt(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind, opterr, optopt;
	int c;

	if (argc <= 1)
		usage(0, NULL);
	opterr = 0; /* Dont yell error's, they are processed by the modules */

	optind = 1;
	while ((c = getopt (argc, argv, "+SFi:s:l:h")) != -1)
	{
		switch(c)
		{
		case 'F':
			opt.flags |= FL_OPT_INFINITE;
			break;
		case 'S':
			opt.flags &= ~FL_OPT_SPREADMODE;
			break;
		case 'l':
			opt.hosts_parallel = atoi(optarg);
			break;
#if 1
		case 's':
			opt.src_ip = inet_addr(optarg);
			opt.flags |= FL_OPT_SRC_IP_ISSET;
			break;
#endif
		case 'i':
			opt.device = optarg;
			break;
		case 'h':
			usage(0, NULL);
			break;
		default:
			fprintf(stderr, "Unknown option: -%c, specify command first.\n", optopt);
			usage(0, NULL);
			break;
		}
	}

	opt.argc = argc - optind;
	opt.argvlist = (argv + optind);

	if (opt.argvlist[0] == NULL)
		usage(0, NULL);

	/* if noone added some suboptions with -D <option>... */
	/* if the user didnt added options with -D, use our defaults */

	return 0;
}

int
list_dhcp()
{
	struct _dhcpnfoset *dfs;

	dfs = dhcp_getnfoset();
	printf("DHCP Option list, RFC 1497,1533,1541,1542\n"); 
	while ((++dfs)->name != NULL)
		printf("%4d %s\n", dfs->tag, dfs->name);


    return 0;
}

char *
getmy_range(void)
{
        char buf1[64];

        snprintf(buf1, sizeof buf1, "%s", int_ntoa(htonl(opt.net + 1)));
        snprintf(opt.myrange, sizeof opt.myrange, "%s-%s", buf1, int_ntoa(htonl(opt.bcast - 1)));

        return opt.myrange;
}

/*
 * Print 1-line status to stderr.
 */
static void
status_out()
{
	char buf[81];
	struct pcap_stat ps;
	float perc = 0;
	unsigned int ip = htonl(IP_current(&opt.ipr));
	long int min = (unsigned long)time(NULL) - time_start;
	long int sec = min % 60;

	min = min / 60;

	memset(&ps, 0, sizeof ps);
	if (opt.ip_socket)
		thcrut_pcap_stats(opt.ip_socket, &ps);

	if (opt.ipr.total)
		perc = ((float)opt.ipr.tot_used * 100) / opt.ipr.total;

	snprintf(buf, sizeof buf, "%02ld:%02ld %-15s %u received, %u dropped. %u done (%02.1f%%)\n", min, sec, ip?int_ntoa(ip):"<done>", ps.ps_recv, ps.ps_drop, opt.ipr.tot_used, (float)perc);
	fprintf(stderr, "%s", buf);

}

static void
sighandler(int sig)
{
	if ((sig == SIGINT) || (sig == SIGTERM))
	{
		tty_dinit();
		_exit(0);
	}
	status_out();
}

int
main(int argc, char *argv[])
{
#if 0
	char buf[1024];

	perlstring(buf, sizeof buf, argv[1], strlen(argv[1]));
	printf("\"%s\"\n", buf);
	exit(0);
#endif
	init_vars();			/* set default values 	*/
	do_getopt(argc, argv);

	if ((opt.argvlist[0] == NULL) || (strlen(opt.argvlist[0]) < 2))
		usage(0, "Unknown command");

	signal(SIGQUIT, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	tty_init();

	switch (*(opt.argvlist[0] + 1))
	{
	case 'i': /* dIscover */
		scanner_main(opt.argc, opt.argvlist);
		break;
	case 'h': /* dHcp */
		dhcp_main(opt.argc, opt.argvlist);
		break;
	case 'r': /* aRp */
		arp_main(opt.argc, opt.argvlist);
		break;
	case 'c': /* iCmp */
		icmp_main(opt.argc, opt.argvlist);
		break;
	default:
		usage(0, "Unknown command");
	}

	tty_dinit();
	exit(0);  /* for specific reasons */
	return 0;
}
