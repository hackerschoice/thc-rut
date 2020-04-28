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
static size_t sendicmp(struct _state_icmp *, size_t len);

#define DFL_HOSTS_PARALLEL	(200)

#define STATE_RESET	(0)
#define STATE_ICMPI	(1)
#define STATE_ICMPII	(2)
#define STATE_ICMPIII	(3)

extern struct _opt opt;

static libnet_ptag_t ln_ip;
static libnet_ptag_t ln_echo;
static libnet_ptag_t ln_tstamp;
static libnet_ptag_t ln_amask;
static libnet_ptag_t ln_rsol;

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
}

static void
usage(void)
{
	fprintf(stderr, ""
"usage: icmp [options] [IP range] ...\n"
" -P            ICMP echo request (default)\n"
" -T            ICMP Timestamp Request (obsolete)\n"
" -A            ICMP Address mask request (obsolete)\n"
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
	while ( (c = getopt(argc, argv, "+TPARh:l:")) != -1)
	{
		switch (c)
		{
		case 'P':
			state->flags |= FL_ST_ECHO;
			break;
		case 'A':
			state->flags |= FL_ST_AMASK;
			break;
		case 'T':
			state->flags |= FL_ST_TREQ;
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

	if (!(state->flags & (FL_ST_ECHO | FL_ST_AMASK | FL_ST_RSOL | FL_ST_TREQ)))
		state->flags |= FL_ST_ECHO;
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
	struct timeval tv;

	if (state->flags == 0)
	{
		fprintf(stderr, "%s:%d SHOULD NOT HAPPEN\n", __func__, __LINE__);
		abort();
	}

	gettimeofday(&tv, NULL);

	if (state->flags & FL_ST_ECHO)
	{
		ln_echo = libnet_build_icmpv4_echo(ICMP_ECHO,
		0,
		0, /* crc */
		opt.ic_id,
		seq, /* HBO */
		(uint8_t *)&tv,
		sizeof tv,
		opt.ln_ctx,
		ln_echo);

		if (sendicmp(state, LIBNET_ICMPV4_ECHO_H + sizeof tv) == 0)
			return 0;
	}

	if (state->flags & FL_ST_TREQ)
	{
		uint32_t ms;
		ms = ((tv.tv_sec * 1000) + (tv.tv_usec / 1000)) % (24*60*60*1000);
		ln_tstamp = libnet_build_icmpv4_timestamp(ICMP_TSTAMP,
		0,
		0, /* crc */
		opt.ic_id,
		seq, /* HBO */
		ms,	/* otime */
		0,	/* rtime */
		0,	/* ttime */
		NULL,
		0,
		opt.ln_ctx,
		ln_tstamp);

		if (sendicmp(state, LIBNET_ICMPV4_TS_H) == 0)
			return 0;
	}
#if 1
	/* Almost no routers/hosts answer to this request any longer... */
	if (state->flags & FL_ST_AMASK)
	{
		uint32_t amask = 0;

		ln_amask = libnet_build_icmpv4_mask(ICMP_MASKREQ,
		0,
		0, /* crc */
		opt.ic_id,
		seq, /* HBO */
		amask,
		NULL,
		0,
		opt.ln_ctx,
		ln_amask);

		if (sendicmp(state, LIBNET_ICMPV4_MASK_H) == 0)
			return 0;
	}
#endif

#if 1
	if (state->flags & FL_ST_RSOL)
	{
		/* Libnet has no support for RSOL so we hack it into ECHO */
		ln_rsol = libnet_build_icmpv4_echo(ICMP_ROUTERSOLICIT, 
		0,
		0, /* crc */
		0, /* rsol, reserved */
		0, /* rsol, reserved */
		NULL,
		0,
		opt.ln_ctx,
		ln_rsol);

		if (sendicmp(state, 8 + 0) == 0)
			return 0;
	}
#endif

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
sendicmp(struct _state_icmp *state, size_t len)
{
	ln_ip  = libnet_build_ipv4(
		LIBNET_ICMPV4_H + len,
		0,
		opt.ip_id,
		0,
		128,
		IPPROTO_ICMP,
		0,
		opt.src_ip,
		STATE_ip(state),
		NULL,
		0,
		opt.ln_ctx,
		ln_ip);

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
	if (!(state = (struct _state_icmp *)STATE_by_ip(&opt.sq, ip->ip_src.s_addr)))
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
				printf("%ld.%03d sec\n", diff.tv_sec, diff.tv_usec / 1000);
			else if (diff.tv_usec / 1000)
				printf("%d.%03d msec\n", diff.tv_usec / 1000, diff.tv_usec % 1000);
			else
				printf("%d usec\n", diff.tv_usec % 1000);
		}
		goto end;
	}
	if ((icmp->icmp_type == ICMP_MASKREPLY) && (len >= 8 + 4))
	{
		if (state->flags & FL_ST_AMASK)
		{
			state->flags &= ~FL_ST_AMASK;
			printf("%-16s icmp_seq=%d ttl=%03d mask=", int_ntoa(ip->ip_src.s_addr), ntohs(icmp->icmp_hun.ih_idseq.icd_seq), ip->ip_ttl);
			printf("%s\n", int_ntoa(*(long *)((char *)icmp + 8)));
		}
		goto end;
	}
	if (icmp->icmp_type == ICMP_TSTAMPREPLY)
	{
		if (state->flags & FL_ST_TREQ)
		{
			state->flags &= ~FL_ST_TREQ;
			printf("%-16s %d bytes reply time request\n", int_ntoa(ip->ip_src.s_addr), 20 + options + len);
		}

		goto end;
	}
	if (icmp->icmp_type == ICMP_ROUTERADVERT)
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
			STATE_ip(&state) = htonl(IP_current(&ipr));
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

