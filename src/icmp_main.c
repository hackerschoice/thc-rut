/*
 * $Id:$
 */

#include "default.h"
#include <stdarg.h>
#include <time.h>
#include "network.h"
#include "network_raw.h"
#include "thc-rut.h"
#include "thcrut_pcap.h"
#include "packets.h"
#include "icmp_main.h"
#include "thcrut_pcap.h"

static void init_defaults(void);
static void init_vars(void);
static void do_getopt(int argc, char *argv[], struct _state_icmp *state);
static void usage(void);
static void icmp_filter(unsigned char *u, struct pcap_pkthdr *p, unsigned char *packet);
static void dis_timeout(struct _state *state);
static void cb_filter(void);
static size_t sendicmp(struct _state_icmp *state, uint8_t *data, size_t len);

static uint8_t packet_echo[8 + 8];
static uint8_t packet_amask[8 + 4];
static uint8_t packet_rsol[8];

#define DFL_HOSTS_PARALLEL	(200)

#define STATE_RESET	(0)
#define STATE_ICMPI	(1)
#define STATE_ICMPII	(2)
#define STATE_ICMPIII	(3)

//extern libnet_t rawsox;
extern struct _opt opt;

static libnet_ptag_t ln_ip;

static void
init_defaults(void)
{
	if (opt.hosts_parallel == 0)
		opt.hosts_parallel = DFL_HOSTS_PARALLEL;
}

static void
init_vars(void)
{
	opt.ip_socket = init_pcap(opt.device, 1, "icmp", &opt.net, &opt.bcast, &opt.dlt_len);

	opt.ln_ctx = net_sock_raw();
	if (opt.ln_ctx == NULL)
	{
		fprintf(stderr, "socket: %s\n", strerror(errno));
		exit(-1);
	}

	icmp_gen_packets(packet_echo, sizeof packet_echo, packet_amask, sizeof packet_amask, packet_rsol, sizeof packet_rsol);
}

static void
usage(void)
{
	fprintf(stderr, ""
"usage: icmp [options] [IP range] ...\n"
" -P            ICMP echo request (default)\n"
" -A            ICMP Address mask request (default)\n"
" -R            ICMP MCAST Router solicitation request\n"
/* Spoofing not possible because we dont reply to arp requests */
//" -s <ip>       Source ip to use\n"
" -l <n>        Hosts in parallel (%d)\n"
"", DFL_HOSTS_PARALLEL);

	exit(0);
}


static void
do_getopt(int argc, char *argv[], struct _state_icmp *state)
{
	int c;

	optind = 1;
	while ( (c = getopt(argc, argv, "+PARh:l:")) != -1)
	{
		switch (c)
		{
		case 'P':
			state->flags |= FL_ST_ECHO;
			break;
		case 'A':
			state->flags |= FL_ST_AMASK;
			break;
		case 'R':
			state->flags |= FL_ST_RSOL;
			break;
		case 'l':
			opt.hosts_parallel = atoi(optarg);
			break;
		default:
			usage();
			break;
		}
	}

	opt.argvlist = &argv[optind];
	opt.argc = argc - optind;

	if (opt.argc <= 0)
		usage();

	if (!(state->flags & (FL_ST_ECHO | FL_ST_AMASK | FL_ST_RSOL)))
		state->flags |= FL_ST_AMASK | FL_ST_ECHO;
}

/*
 * Return 0 if blocked.
 * FIXME: Can happen that we always get blocked after second
 * ICMP type is send out. In any case do we repeat and send
 * first ICMP type again.
 */
static int
sendpackets(struct _state_icmp *state, unsigned int seq)
{
	struct icmp *icmp;
	struct timeval *tv;

	if (state->flags == 0)
	{
		fprintf(stderr, "%s:%d SHOULD NOT HAPPEN\n", __func__, __LINE__);
		abort();
	}


	if (state->flags & FL_ST_ECHO)
	{
		icmp = (struct icmp *)(packet_echo);
		icmp->icmp_hun.ih_idseq.icd_seq = htons(seq);
		tv = (struct timeval *)(packet_echo + 8);
		gettimeofday(tv, NULL);
		if (sendicmp(state, packet_echo, sizeof packet_echo) == 0)
			return 0;
	}
	if (state->flags & FL_ST_AMASK)
	{
		icmp = (struct icmp *)(packet_amask);
		icmp->icmp_hun.ih_idseq.icd_seq = htons(seq);
		if (sendicmp(state, packet_amask, sizeof packet_amask) == 0)
			return 0;
	}

	if (state->flags & FL_ST_RSOL)
		if (sendicmp(state, packet_rsol, sizeof packet_rsol) == 0)
			return 0;
	return 1;
}

/*
 * FIXME: On block'ed send we should use wfds to see when socket
 * becomes writeable again. (But this would delay our queue :/).
 */
static void
dis_timeout(struct _state *state)
{
	struct _state_icmp *state_icmp = (struct _state_icmp *)state;

	/* Switch state if we send successfully, otherwise
	 * stay in state to try again.
	 */
	switch (STATE_current(state))
	{
	case STATE_RESET:
		if (sendpackets(state_icmp, 0) != 0)
			STATE_current(state) = STATE_ICMPI;
		break;
	case STATE_ICMPI:
		if (sendpackets(state_icmp, 1) != 0)
			STATE_current(state) = STATE_ICMPII;
		break;
	case STATE_ICMPII:
		if (sendpackets(state_icmp, 2) != 0)
			STATE_current(state) = STATE_ICMPIII;
		break;
	case STATE_ICMPIII:
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
	if (pcap_dispatch(opt.ip_socket, -1, (pcap_handler) icmp_filter, NULL) < 0)
	{
		pcap_perror(opt.ip_socket, "pcap_dispatch");
		exit(-1);
	}
}

#ifndef LIBNET_IPV4_H
# define LIBNET_IPV4_H	0x14
#endif

/*
 * Return number 0 if blocked, -1 on error >0 otherwise.
 */
static size_t
sendicmp(struct _state_icmp *state, uint8_t *data, size_t len)
{
#if 0
	struct ip *ip = (struct ip *)(data);

	ip->ip_dst.s_addr = htonl(STATE_ip(state));
	DEBUGF("ip len= %d\n", ntohs(ip->ip_len));
#endif

	ln_ip  = libnet_build_ipv4(
		/*LIBNET_ICMPV4_H + */len,
		0,
		31337,
		0,
		128,
		IPPROTO_ICMP,
		0,
		opt.src_ip,
		STATE_ip(state),
		data,
		len,
		opt.ln_ctx,
		ln_ip);

	/* ICMP checksum is mandatory. FIXME  */

	return net_send(opt.ln_ctx);
}

static void
icmp_filter(unsigned char *u, struct pcap_pkthdr *p, unsigned char *packet)
{
	char buf[128];
	struct ip *ip = (struct ip *)(buf);
	struct _state_icmp *state;
	int len;
	unsigned short options = 0;
	struct icmp *icmp;
	struct timeval diff, *tv;

	/* 
	 * At least...
	 */
	if (p->caplen < (opt.dlt_len + 20 + 8))
		return;

	len = p->caplen - opt.dlt_len;
	if (len > sizeof buf)
		len = sizeof buf;

	memcpy(buf, packet + opt.dlt_len, len);
	if (vrfy_ip(ip, len, &options) != 0)
		return;
	if (!(state = (struct _state_icmp *)STATE_by_ip(&opt.sq, ntohl(ip->ip_src.s_addr))))
		return;

	if (ntohs(ip->ip_len) > len)
		return;
	len = ntohs(ip->ip_len) - 20 - options;

	icmp = (struct icmp *)(buf + 20 + options);
	if (((icmp->icmp_type == 0) && (icmp->icmp_code == 0)) && (len >= 8 + 8))
	{
		if (state->flags & FL_ST_ECHO)
		{
			state->flags &= ~FL_ST_ECHO;
			tv = (struct timeval *)((char *)icmp + 8);
			SQ_TV_diff(&diff, tv, &p->ts);
			/* ttl= time= xx.yyy msec */
			printf("%-16s %d bytes reply icmp_seq=%d ttl=%03d time=", int_ntoa(ip->ip_src.s_addr), 20 + options + len, ntohs(icmp->icmp_hun.ih_idseq.icd_seq), ip->ip_ttl);
			if (diff.tv_sec)
				printf("%ld.%03ld sec\n", diff.tv_sec, diff.tv_usec / 1000);
			else if (diff.tv_usec / 1000)
				printf("%ld.%03ld msec\n", diff.tv_usec / 1000, diff.tv_usec % 1000);
			else
				printf("%ld usec\n", diff.tv_usec % 1000);
		}
		goto end;
	}
	if ((icmp->icmp_type == 18) && (len >= 8 + 4))
	{
		if (state->flags & FL_ST_AMASK)
		{
			state->flags &= ~FL_ST_AMASK;
			printf("%-16s icmp_seq=%d ttl=%03d mask=", int_ntoa(ip->ip_src.s_addr), ntohs(icmp->icmp_hun.ih_idseq.icd_seq), ip->ip_ttl);
			printf("%s\n", int_ntoa(*(long *)((char *)icmp + 8)));
		}
		goto end;
	}
	if (icmp->icmp_type == 9)
	{
		if (state->flags & FL_ST_RSOL)
		{
			state->flags &= FL_ST_RSOL;
			printf("%s ROUTER SOLICITATION. DECODING NOT IMPLEMENTED. FIXME\n", int_ntoa(ip->ip_src.s_addr));
		}
		goto end;
	}
#if 0
	/* We dont sniff for this one */
	DEBUGF("type %d, code %d\n", icmp->type, icmp->code);
	hexdump(buf, 24);
#endif
end:
	if (!state->flags)
		STATE_reset(state);
}

int
icmp_main(int argc, char *argv[])
{
	struct _ipranges ipr;
	struct _state_icmp state;
	struct pcap_stat ps;
	int ret;

	init_defaults();
	memset(&state, 0, sizeof state);
	do_getopt(argc, argv, &state);
	init_vars();
	IP_init(&ipr, opt.argvlist,  (opt.flags & FL_OPT_SPREADMODE)?IPR_MODE_SPREAD:0);

	if (!SQ_init(&opt.sq, opt.hosts_parallel, sizeof state, pcap_fileno(opt.ip_socket), dis_timeout, cb_filter))
	{
		fprintf(stderr, "Failed to init states: %s\n", strerror(errno));
		exit(-1);
	}

	while (1)
	{
		IP_next(&ipr);
		if (IP_current(&ipr))
		{
			STATE_ip(&state) = IP_current(&ipr);
			ret = STATE_wait(&opt.sq, (struct _state *)&state);
		} else
			ret = STATE_wait(&opt.sq, NULL);

		if (ret != 0)
			break;
	}

	if (thcrut_pcap_stats(opt.ip_socket, &ps) == 0)
		fprintf(stderr, "%u packets received by filter, %u packets dropped by kernel\n", ps.ps_recv, ps.ps_drop);

	return 0;
}

