/*
 * $Id: discover_dispatch.c,v 1.8 2003/05/25 18:19:16 skyper Exp $
 *
 * Timeout handling and dispatcher function for delay slot.
 */

#include "default.h"
#include <sys/time.h>
#include <time.h>
#include <pcap.h>
#include <libnet.h>
#include "thc-rut.h"
#include "state.h"
#include "range.h"
#include "thcrut_pcap.h"
#include "thcrut_sig.h"
#include "network_raw.h"
#include "nmap_compat.h"
#include "packets.h"
#include "system.h"
#include "discover_dispatch.h"
#include "nvt.h"
#include "asn.h"
#include "network.h"

extern struct _opt opt;

typedef void (*dispatch_func_recv_t)(struct _state_fp *state, struct pcap_pkthdr *p, uint8_t *packet);

static void sendudp(struct _state_fp *state, unsigned short port, uint8_t *data, size_t len);
static void sendicmp(struct _state *state, uint8_t *data, size_t len);
static void dis_sendtcp(struct _state *state, unsigned short port);
static void dis_sendfpI(struct _state_fp *state, void *user);
static void dis_tcpwrite(struct _state_fp *state);
static void dis_tcpread(struct _state_fp *state);
static void dis_end(struct _state_fp *state);
static void dis_end_dis(struct _state_fp *state);
static void dis_end_fp(struct _state_fp *state);
static void dis_end_nmapfp(struct _state_fp *state);
static void dis_recvdummy(struct _state_fp *state, struct pcap_pkthdr *p, uint8_t *packet);
static void dis_recv(struct _state_fp *state, struct pcap_pkthdr *p, uint8_t *packet);
static void dis_recvfpI(struct _state_fp *state, struct pcap_pkthdr *p, uint8_t *packet);

static void tcp_open(struct _state_fp *state, unsigned short port);
static int fp_state_next_switch(struct _state_fp *state);
static void fp_state_exec(struct _state_fp *state);
void fp_output(char *results);

#define TOUT_TCP_CONN_EST	(5)
#define TOUT_TCP_READ		(35)

#define STATE_RESET		(0)  /* NULL function */
#define STATE_SENDTCP80I	(1)
#define STATE_SENDTCP80II	(2)
#define STATE_SENDTCP80III	(3)
#define STATE_SENDTCP64kI       (4)  /* Try a High Port */
#define STATE_SENDTCP64kII      (5)  /* Try a High Port */
#define STATE_SENDTCP0I         (6)  /* Try a Low Port */
#define STATE_ICMP_ECHOI	(7)
#define STATE_ICMP_ECHOII	(8)
#define STATE_SENDTCP22I        (9)  /* try SSH Port    */
#define STATE_SENDTCP22II       (10)  /* try SSH Port    */
#define STATE_DISCOVERY_MAX     (10)  /* Upper bound of discovery states */

#define STATE_SENDFPI		(11) /* Nmap Test 1              */
#define STATE_SENDFPII		(12) /* Nmap Test 1 (second try) */
#define STATE_SENDFP_FIRST	(13) /* Port characteristic and banner */
#define STATE_SENDFP_SECOND	(14)
#define STATE_END		(15)
#define STATE_TCP		(16)
#define STATE_TCPWRITE		(17)
#define STATE_TCPREAD		(18)


uint8_t ip_tcp_sync[20];
uint8_t ip_tcp_fp[40];
uint8_t ip_udp_dcebind[8 + FP_DCEBIND_LEN];
uint8_t ip_udp_snmp[8 + FP_SNMP_LEN];
uint8_t ip_icmp_echo[8];

unsigned short ip_tcp_sync_chksum;
unsigned short ip_tcp_fp_chksum;
struct sockaddr_in ip_tcp_sync_addr;
static dispatch_func_recv_t dispatch_funcs[] = {
	dis_recvdummy,
	dis_recv,
	dis_recv,
	dis_recv,
	dis_recv,
	dis_recv,
	dis_recv,
	dis_recv,
	dis_recv,
	dis_recv,
	dis_recv,
	dis_recvfpI,
	dis_recvfpI,
	dis_recv,   /* STATE_SENDFP_FIRST  */
	dis_recv};  /* STATE_SENDFP_SECOND */

//extern libnet_t rawsox;
static libnet_ptag_t ln_ip;

/*
 * Switch to next FP state for fingerprinting.
 * Return 0 on success, -1 on error (no tests left).
 * This call should be followed by a call to fp_state_exec().
 */
static int
fp_state_next_switch(struct _state_fp *state)
{
	state->testnr++;
	if (state->testnr >= opt.fpts.cat[state->cat].n_tests)
	{
next:
		state->cat++;
		if (state->cat >= sizeof opt.fpts.cat / sizeof *opt.fpts.cat)
		{
			state->cat = 7;
			return -1;  /* STATE_reset(state); */
		}
		if (opt.fpts.cat[state->cat].n_tests == 0)
			goto next;

		state->testnr = 0;
	}

	fp_state_exec(state);

	return 0;
}

/*
 * Send packet in current FP state and perform a STATE_switch
 * if required.
 */
static void
fp_state_exec(struct _state_fp *state)
{
	/* CALL THE CORRESPONDING FUNCTION */
	switch (state->cat)
	{
	case FP_CAT_TCP:
		STATE_current(state) = STATE_SENDFP_FIRST;
		dis_sendtcp((struct _state *)state, opt.fpts.cat[FP_CAT_TCP].tests[state->testnr].port);
		break;
	case FP_CAT_UDP:
		STATE_current(state) = STATE_SENDFP_FIRST;
		/* FIXME */
		sendudp(state, opt.fpts.cat[FP_CAT_UDP].tests[state->testnr].port, ip_udp_dcebind, 8 + FP_DCEBIND_LEN);
//		fprintf(stderr, "%s UDP NOT SUPPORTED\n", __func__);
		break;
	case FP_CAT_BANNER:
		tcp_open(state, opt.fpts.cat[state->cat].tests[state->testnr].port);
		STATE_current(state) = STATE_TCPREAD;
		break;
	case FP_CAT_WWW:
		tcp_open(state, opt.fpts.cat[state->cat].tests[state->testnr].port);
		STATE_current(state) = STATE_TCPWRITE;
		break;
	case FP_CAT_SNMP:
		STATE_current(state) = STATE_SENDFP_FIRST;
		sendudp(state, opt.fpts.cat[FP_CAT_SNMP].tests[state->testnr].port, ip_udp_snmp, 8 + FP_SNMP_LEN);
		break;
	case FP_CAT_NVT:
		STATE_current(state) = STATE_TCPREAD;
		tcp_open(state, opt.fpts.cat[state->cat].tests[state->testnr].port);
		break;
	default:
		fprintf(stderr, "%s: Unknown FP category %d for %s\n", __func__, state->cat, int_ntoa(STATE_ip(state)));
		hexdump((uint8_t *)state, opt.sq.item_size);
	}
}


/*
 * Called if a state time'd out.
 * Caller should check the state afterwards. It might have been freed
 * by the state handling function (this or any other function).
 *
 * The discovery is split into 3 steps:
 *
 *                    +=================+
 *        +--------> ||  START (new IP) ||
 *        |           +=================+
 *        |                   |
 *        |        +-----------------------+
 *        |        |  Host online          |
 *        +- NO -<-| (TCP to various ports |->-- YES --+
 *                 +-----------------------+ +---------+-----------------+
 *                                           | Port State Fingerprinting |
 *                                           +---------+-----------------+
 *                                                     |
 *                                             NMAP OS Fingerprinting
 *
 * (bad ascii art eh? no need for state deagram. We always
 * do Fingerprinting if host has been found)
 *
 * Host discovery can be skipped and the FP can be forced.
 * Host discovery without FP is possible.
 */
void
dis_timeout(struct _state *state)
{
	struct _state_dis *state_dis = (struct _state_dis *)state;
	struct _state_fp *state_fp = (struct _state_fp *)state;
	/*
	 * a small state struct is passed if we just do
	 * discovery, otherwise we have a larger state_fp
	 * struct. Care should be taken what is written to
	 * which one. port and flags lie in state_fp for example
	 * and should never be written to if we are just doing
	 * host discovery.
	 */

	/*
	 * First of all check if there is pending data in the
	 * send buffer that still needs to be flushed through
	 * the raw socket. On success reset send buffer and
	 * reschedule the state.
	 */
	if (state_dis->slen != 0)
	{
		ln_ip = libnet_build_ipv4(
			state_dis->slen,
			0,
			31337,
			0,
			128,
			state_dis->proto,
			0,
			opt.src_ip,
			state_dis->dst_ip,
			state_dis->sbuf,
			state_dis->slen,
			opt.ln_ctx,
			ln_ip);

		if (net_send(opt.ln_ctx) != 0)
			state_dis->slen = 0;
		/* No need to reschedule. We get called again in 1 second */

		return;
	}

	/*
	 * What we should try in fact is
	 * TCP 80
	 * TCP64k
	 * ICMP PING
	 * TCP0
	 */
	switch (STATE_current(state))
	{

	case STATE_RESET:  /* START */
		if (opt.flags & FL_OPT_HOSTDISCOVERY)
		{
			STATE_current(state) = STATE_SENDTCP80I;
			dis_sendtcp(state, 80);
		} else if (opt.flags & FL_OPT_FP) {
			/* Execute first state */
			fp_state_exec(state_fp);
		}
		break;
	/* -----BEGIN HOST DISCOVERY------ */
	case STATE_SENDTCP80I:
		if (opt.flags & FL_OPT_FP)
			state_fp->port = 80;  /* save so that NMAP is faster */
		STATE_current(state) = STATE_SENDTCP80II;
		dis_sendtcp(state, 80);
		break;
	case STATE_SENDTCP80II:
		STATE_current(state) = STATE_SENDTCP80III;

		//dis_sendtcp(state, 65535);
		sendicmp(state, ip_icmp_echo, sizeof ip_icmp_echo);
		//dis_sendtcp(state, 0);

		dis_sendtcp(state, 80);
		break;
	case STATE_SENDTCP80III:
		STATE_current(state) = STATE_SENDTCP22I;

		//sendicmp(state, ip_icmp_echo, sizeof ip_icmp_echo);
		//dis_sendtcp(state, 0);
		dis_sendtcp(state, 65535);

		if (opt.flags & FL_OPT_FP)
			state_fp->port = 22;  /* save so that NMAP is faster */
		dis_sendtcp(state, 22);
		break;
#if 0
	case STATE_SENDTCP64kI:
		STATE_current(state) = STATE_SENDTCP64kII;
		dis_sendtcp(state, 65535);
		sendicmp(state, ip_icmp_echo, sizeof ip_icmp_echo);
		dis_sendtcp(state, 0);
//		dis_sendtcp(state, 0); /* Low Port */
		break;
#endif
#if 0
	case STATE_SENDTCP64kI:
		if (opt.flags & FL_OPT_FP)
			state_fp->port = 22;  /* save so that NMAP is faster */
		STATE_current(state) = STATE_SENDTCP22I;
		dis_sendtcp(state, 22);
		STATE_current(state) = STATE_SENDTCP0I;
		sendicmp(state, ip_icmp_echo, sizeof ip_icmp_echo);
		break;
	case STATE_SENDTCP0I:
		STATE_current(state) = STATE_ICMP_ECHOI;
		sendicmp(state, ip_icmp_echo, sizeof ip_icmp_echo);
		break;
	case STATE_ICMP_ECHOI:
		STATE_current(state) = STATE_ICMP_ECHOII;
		sendicmp(state, ip_icmp_echo, sizeof ip_icmp_echo);
		break;
	case STATE_ICMP_ECHOII:
		if (opt.flags & FL_OPT_FP)
			state_fp->port = 22;  /* save so that NMAP is faster */
		STATE_current(state) = STATE_SENDTCP22I;
		dis_sendtcp(state, 22);
		break;
#endif
	case STATE_SENDTCP22I:
		STATE_current(state) = STATE_SENDTCP22II;
		dis_sendtcp(state, 0);
		dis_sendtcp(state, 22);
		break;
	case STATE_SENDTCP22II:
		/* Timeout in last discovery slot. No asnwer at all */
		STATE_reset(state);  /* RESET */
		break;
	/* -----END HOST DISCOVERY----- */
	/* -----BEGIN PORT STATE BANNER OS FP----- */
	case STATE_TCPREAD:
		dis_tcpread(state_fp);
		break;
	case STATE_TCPWRITE:
		dis_tcpwrite(state_fp);
		break;

	case STATE_SENDFP_FIRST:  /* Timeout occured */
		fp_state_exec(state_fp);
		STATE_current(state) = STATE_SENDFP_SECOND;
		break;
	case STATE_SENDFP_SECOND:
		/* port state test */
		if (fp_state_next_switch(state_fp) != 0)
			dis_end_fp(state_fp);
		break;
	/* -----END PORT STATE BANNER OS FP----- */
	/* -----BEGIN NMAP OS FP----- */
	case STATE_SENDFPI:
		dis_sendfpI(state_fp, NULL);
		break;
	case STATE_SENDFPII:
		/* FIXME: Why do we break here already? */
		if (state_fp->flags & STATE_FOUND_OPEN_PORT)
		{
			dis_end_nmapfp(state_fp);
			break;
		}
		STATE_current(state_fp) = 0;
		dis_sendfpI(state_fp, NULL);
		break;
	/* -----END NMAP OS FP----- */
	case STATE_END:
		STATE_reset(state);
		fprintf(stderr, "%s:%d STATE_END timed out for ip %s. Should not happen\n", __func__, __LINE__, int_ntoa(STATE_ip(state)));
		break;
	default:
		fprintf(stderr, "Unknown state: %d\n", STATE_current(state));
		STATE_reset(state);
	}
}


#if 0
/*
 * Change IP in ip packet and fix the tcp checksum
 */
static void
packetfixup(char *buf, unsigned short chksum, long newip)
{
	int sum;

	*(long *)(buf + 16) = newip;
	sum = chksum;
	sum = ~sum;
	sum += *(unsigned short *)(buf + 16);
	sum += *(unsigned short *)(buf + 18);
	sum = ~sum;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	*(unsigned short *)(buf + 36) = sum;
}
#endif

static void
tcp_open(struct _state_fp *state, unsigned short port)
{
	struct sockaddr_in addr;
	int on = 1;

	memset(&addr, 0, sizeof addr);
	addr.sin_family = PF_INET;
	addr.sin_addr.s_addr = htonl(STATE_ip(state));
	addr.sin_port = htons(port);

	state->flags &= ~STATE_CRLF_SENT;
	state->sox = socket(PF_INET, SOCK_STREAM, 0);
	if (state->sox < 0)
	{
		fprintf(stderr, "socket: %s\n", strerror(errno));
		STATE_reset(state);
		return;
	}

	setsockopt(state->sox, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
	/* We are only interested in the first 128 bytes..even less */
	/* On Linux this is rouned up to at least 192 bytes */
	on = 2048; /* To get full FTP banner */
	setsockopt(state->sox, SOL_SOCKET, SO_RCVBUF, &on, sizeof on);
	if (fcntl(state->sox, F_SETFL, O_NONBLOCK) != 0)
	{
		fprintf(stderr, "fcntl: %s\n", strerror(errno));
		STATE_reset(state)
		return;
	}
	connect(state->sox, (struct sockaddr *)&addr, sizeof addr);
	state->un.turn = 0;
}

//#define HTTP_HEAD	"HEAD / HTTP/1.0\r\n\r\n"
#define HTTP_HEAD	"GET / HTTP/1.0\r\n\r\n"

static void
dis_tcpwrite(struct _state_fp *state)
{
	char ok = 0;

	if (state->cat == FP_CAT_WWW)
		ok = (write(state->sox, HTTP_HEAD, sizeof HTTP_HEAD - 1) == sizeof HTTP_HEAD -1);
		
	if (!ok)
	{
		/*
		 * We give us 5 seconds to connect.
		 * on RST we have ECONNREFUSED set.
		 */
		if ((errno == EAGAIN) || (errno == EINPROGRESS) || (errno == EWOULDBLOCK))
		{
			state->un.turn++;
			if (state->un.turn <= TOUT_TCP_CONN_EST)
				return;
		}
		shutdown(state->sox, 2);
		close(state->sox);

		/*
		 * No need to reschedule. This is function is called
		 * on timeout.
		 */
		if (fp_state_next_switch(state) != 0)
			dis_end_fp(state);

		return;
	}

	state->un.turn = TOUT_TCP_CONN_EST + 1; /* is connected */

	/* who writes will also read */
	STATE_switch(state, STATE_TCPREAD);
}

/*
 * Dispatcher function.
 * Discovery ended.
 */
static void
dis_end_dis(struct _state_fp *state)
{
	struct _binout binout;
	int ret = 0;

	if (opt.flags & FL_OPT_FP)
	{
		if (opt.flags & FL_OPT_BINOUT)
		{
			memset(&binout, 0, sizeof binout);
			binout.len = htons(sizeof binout);
			binout.ip = htonl(STATE_ip(state));
			ret = write(1, &binout, sizeof binout);
			if (ret < 0)
				ERREXIT("write(1): %d\n", ret);
		}
		fp_state_exec(state);
	} else {
		dis_end(state);
	}
}

/*
 * Portstate/Banner FP ended, start NMAP OS FP
 */
static void
dis_end_fp(struct _state_fp *state)
{
	state->un.ptr = NULL;
#ifdef WITH_NMAPFP
	/* We enter with unkown state. This makes him resend
	 * everytng twice.
	 */
	dis_sendfpI(state, NULL);
#else
	/* Skip NMAP FP */
	dis_end_nmapfp(state);	
#endif
}

static void
dis_end_nmapfp(struct _state_fp *state)
{
	dis_end(state);
}

/*
 * Input:
 *   data of length len
 *   dst must be 1 byte longer than the input string.
 *
 * Output:
 *   \0 terminated and stripped string
 *   Stripped means that all occurences of multiple non-printable chars
 *   are removed.
 *
 * Return:
 *   length (without \0) of the resulting string.
 *
 */
static int
strip(char *dst, char *data, int len)
{
	char c;
	char last = 0;
	char *ptr = dst;

	while (len-- > 0)
	{
		c = *data++;

		/* Ignore \x00 */
		if (!c)
			continue;

		if (c == '\r')
			c = '\n';

		if (((c >= 0x21) && (c <= 0x7e)) || (c != last))
		{
			*dst++ = c;
		}

		last = c;
	}

	*dst = '\0';

	return dst - ptr;
}

/*
 * This function is only called from the timeout handler
 * and the state is automatilcy rescheduled after return.
 *
 * We have to set state->reschedule if this function will be
 * called from a filter() function in the future.
 */
static void
dis_tcpread(struct _state_fp *state)
{
	char buf[2048];
	char ans[2048 + 1 + 2];  /* NVT answer */
	char rem[2048];  /* NVT rem    */
	int alen, rlen, len;
	char *end;
	char *ptr;
	char *res;
	ssize_t n;
	fd_set wfds;
	struct timeval tv;
	int ret;

	n = read(state->sox, buf, sizeof buf - 1);
	if (n == 0)
		goto end;

	state->un.turn++;
	if (n < 0)
	{
		/*
		 * Bloody hell. Some services try to resolve our
		 * IP and require 30 seconds until they come up with
		 * a banner.
		 * The first 5 seconds are reserved for connection
		 * establishment.
		 */
		if (state->un.turn >= TOUT_TCP_CONN_EST + TOUT_TCP_READ)
			goto end;

		if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINPROGRESS))
		{
			/*
			 * Check if we still try to connect (turn < 5)
			 * or if we got the connection but are waiting for
			 * data (5 < state < 40)
			 *
			 * Is there any decent solution to check the state of
			 * a socket? getsockopt(sox, SOL_SOCK, SO_ERROR, ..)
			 * wont work and also tricks like write(sox, NULL, 0)
			 * indicate that the socket is writeable even if not
			 * connected.
			 */
			if (state->un.turn == TOUT_TCP_CONN_EST)
				goto end;

			/*
			 * If we didnt wrote anything so far
			 * check if we are connected at all.
			 */
			if (state->un.turn < TOUT_TCP_CONN_EST)
			{
				tv.tv_usec = 0;
				tv.tv_sec = 0;
				FD_ZERO(&wfds);
				FD_SET(state->sox, &wfds);
				n = select(state->sox + 1, NULL, &wfds, NULL, &tv);
				if (n > 0)
				{
					state->un.turn = TOUT_TCP_CONN_EST;
					/* Some telnet sessions need a \r\n
					 * to be activated. We immediately send
					 * it.
					 */
					if (state->cat == FP_CAT_NVT)
					{
						ret = write(state->sox, "\r\n", 2);
						if (ret < 0)
							ERREXIT("write() = %d\n", ret);
					}
				}
			}

			/* Let's try again in 1 second */
			/* It's rescheduled anyway */
			//STATE_reschedule(state, 1);
			return;
		}
		goto end;
	} /* n < 0 */

	//fprintf(stderr, "Read %d bytes\n", n);
	if (n > 0)
	{
		if (state->un.turn < TOUT_TCP_CONN_EST)
			state->un.turn = TOUT_TCP_CONN_EST; /* ESTABLISHED */
		buf[n] = '\0';
		switch (state->cat)
		{
		case FP_CAT_NVT:
			NVT_decode(buf, n, ans, &alen, rem, &rlen);
			/* We keep NVT-negotiation + banner */
			len = strip(rem, buf, n);

			res = state->results + opt.fpts.ofs_test_nvt + state->testnr * FP_NTEST_SZ;

			ptr = res;
			while (*res)
				res++;
			memcpy(res, rem, MIN(len, FP_NTEST_SZ - (res - ptr)));
			ptr[FP_NTEST_SZ - 1] = '\0';
			/* FULL */
			if (len + (res - ptr) + 1 >= FP_NTEST_SZ)
				break;
			if ((alen > 0) || (rlen <= 0))
			{
				/*
				 * Push it! Some routers do a NVT negotiation
				 * but then wait for a CRLF.
				 */
				if (!(state->flags & STATE_CRLF_SENT))
				{
					state->flags |= STATE_CRLF_SENT;
					ans[alen++] = '\r';
					ans[alen++] = '\n';
					ret = write(state->sox, ans, alen);
					return;
				}

				/*
				 * NVT Negotiation. Try read again in 1 second.
				 * The might come more..
				 */
				ret = write(state->sox, ans, alen);

				/*
				 * But if we already received some data
				 * then wait exactly 2 seconds longer
				 */
				if ((rlen > 0) && (state->un.turn < TOUT_TCP_CONN_EST + TOUT_TCP_READ - 2))
					state->un.turn = TOUT_TCP_CONN_EST + TOUT_TCP_READ - 2;
				return;
			}
			break;
		case FP_CAT_WWW:
			ptr = strstr(buf, "Server:");
			if (!ptr)
				break;
			ptr += 7;
			if (!(end = strchr(ptr, '\r')))
				end = strchr(ptr, '\n');
			if (!end)
				end = &buf[n];
			else
				*end = '\0';

			res = state->results + opt.fpts.ofs_test_www + state->testnr * FP_WTEST_SZ;
			memcpy(res, ptr, MIN(end - ptr + 1, FP_WTEST_SZ));
			res[FP_WTEST_SZ - 1] = '\0';
			break;
		case FP_CAT_BANNER:
			/*
			 * This is a hack. We try to auto-recognize FTP/smtp
			 * banner and log just the "\n220 " line
			 */
			ptr = buf;
			if (!strncmp("220-", ptr, 4))
			{
				ptr = strstr(ptr, "\n220 ");
				if (ptr)
				{
					ptr++;
					n = n - (ptr - buf);
				} else
					ptr = buf;
			}
			res = state->results + opt.fpts.ofs_test_banner + state->testnr * FP_BTEST_SZ;
			memcpy(res, ptr, MIN(n, FP_BTEST_SZ));
			res[FP_BTEST_SZ - 1] = '\0';
			break;
		default:
			fprintf(stderr, "%s Wrong category\n", __func__);
		}
	}

end:
	shutdown(state->sox, 2);
	close(state->sox);
	/*
	 * Start NMAP OS FP if no port state tests left.
	 * No need to reschedule. This function is called on timeout.
	 */
	if (fp_state_next_switch(state) != 0)
		dis_end_fp(state);
}

#if 0
#define FILLSBUF(state, data, len) do { \
	memcpy(((struct _state_dis *)(state))->sbuf, data, len); \
	((struct _state_dis *)(state))->slen = len; \
} while (0)
#endif
#define FILLSBUF(state, xip, xproto, data, len) do { \
	memcpy(((struct _state_dis *)(state))->sbuf, data, len); \
	((struct _state_dis *)(state))->dst_ip = xip; \
	((struct _state_dis *)(state))->proto = xproto; \
} while (0)

static void
sendicmp(struct _state *state, uint8_t *data, size_t len)
{
#if 0
	struct ip *ip = (struct ip *)(data);
	
	ip->ip_dst.s_addr = htonl(STATE_ip(state));
	libnet_do_checksum(data, IPPROTO_ICMP, len - LIBNET_IP_H);
#endif

	uint32_t dst_ip = STATE_ip(state);

	ln_ip = libnet_build_ipv4(
		len,
		0,
		31337,
		0,
		128,
		IPPROTO_ICMP,
		0,
		opt.src_ip,
		dst_ip,
		data,
		len,
		opt.ln_ctx,
		ln_ip);

	if (net_send(opt.ln_ctx) == 0)
		FILLSBUF(state, dst_ip, IPPROTO_ICMP, data, len);
}

/*
 * Send an empty UDP packet to this port.
 */
static void
sendudp(struct _state_fp *state, unsigned short port, uint8_t *data, size_t len)
{
	uint16_t *dport;

	/* Set DST port */
	dport = (uint16_t *)(data + 2);
	*dport = htons(port);

	uint32_t dst_ip = STATE_ip(state);

	ln_ip = libnet_build_ipv4(
		len,
		0,
		31337,
		0,
		128,
		IPPROTO_UDP,
		0,
		opt.src_ip,
		dst_ip,
		data,
		len,
		opt.ln_ctx,
		ln_ip);

	if (net_send(opt.ln_ctx) == 0)
		FILLSBUF(state, dst_ip, IPPROTO_UDP, data, len);
}

/*
 * Dont switch state here. This is done in calling function.
 */
static void
dis_sendtcp(struct _state *state, unsigned short port)
{
	uint16_t *dport = (uint16_t *)(ip_tcp_sync + 2);
	//struct tcphdr *tcp = (struct tcphdr *)(ip_tcp_sync);
	//struct ip *ip = (struct ip *)(ip_tcp_sync);
	//int src_ip;
	uint32_t dst_ip = STATE_ip(state);

	*dport = htons(port);
	/* src and dst ip must be set for checksum calculation! */
	/* We must set src ip on packet generation (scanner_gen_packets) */
	//tcp->th_dport = htons(port);
	//ip->ip_dst.s_addr = htonl(STATE_ip(state));
	/* The src IP is always set except we use the 'any' device in
	 * which case we have to recalculate it for any packet we send
	 * out.
	 */
#if 0
	src_ip = ip->ip_src.s_addr;
	if (src_ip == 0)
		ip->ip_src.s_addr = getmyip_by_dst(ip->ip_dst.s_addr);
#endif
	ln_ip = libnet_build_ipv4(
		20,
		0,
		31337,
		0,
		128,
		IPPROTO_TCP,
		0,
		opt.src_ip,
		dst_ip,
		ip_tcp_sync,
		20,
		opt.ln_ctx,
		ln_ip);

	//libnet_do_checksum(ip_tcp_sync, IPPROTO_TCP, LIBNET_TCP_H);
	if (net_send(opt.ln_ctx) == 0)
		FILLSBUF(state, dst_ip, IPPROTO_TCP, ip_tcp_sync, 20);

	//ip->ip_src.s_addr = src_ip;  /* Set to 0 again */
}

/*
 * NMAP
 * If we are in this state then the host already responded with
 * a packet (rst probably) and is 'alive'.
 * We search an open port (if not already found).
 */
static void
dis_sendfpI(struct _state_fp *state, void *user_not_used)
{
	//struct ip *ip = (struct ip *)ip_tcp_fp;
	uint16_t *dport = (uint16_t *)(ip_tcp_fp + 2);
	//struct tcphdr *tcp = (struct tcphdr *)(ip_tcp_fp + 20);

	//DEBUGF("%s Starting NMAP OS FP on port %d, %s\n", int_ntoa(STATE_ip(state)), state->port, state->flags & STATE_FOUND_OPEN_PORT?"FOUND":"SEARCHING");
	/*
	 * FIXME: Try every port twice
	 * Timeout handler only calls us if we are in
	 * STATE_SENDFPII. Receiver alwaays calls us with state to SENDFPI.
	 */
	if ((!(state->flags & STATE_FOUND_OPEN_PORT)) && (STATE_current(state) != STATE_SENDFPI))
	{
		switch (state->port)
		{
		case 80:
			state->port = 22;
			break;
		case 22:
			state->port = 139;
			break;
		case 139:
			state->port = 21;
			break;
		case 21:
			state->port = 135;
		case 135:
			state->port = 1025;
			break;
		case 1025:
			state->port = 1029;
			break;
		case 1029:
			/* No open ports found at all */
			/* This will usually call dis_end() and reset the state */
			dis_end_nmapfp(state);
			return;
		default:
			/*
			 * Should only happen if discovery has not been used.
			 * Otherwise did the discovery already checked for
			 * some ports and we skip them (80, 22, 65535).
			 */
//			fprintf(stderr, "%s:%d NMAP searching for open port for %s:%d)\n", __func__, __LINE__, int_ntoa(STATE_ip(state)), state->port);
			state->port = 80;
	//		dis_end_nmapfp(state);
	//		return;
		}
	}

	/*
	 * We check for every port twice unless
	 * we get a RST back.
	 */
	if (STATE_current(state) != STATE_SENDFPI)
		STATE_current(state) = STATE_SENDFPI;
	else
		STATE_current(state) = STATE_SENDFPII;

	uint32_t dst_ip = STATE_ip(state);

	ln_ip = libnet_build_ipv4(
		state->slen,
		0,
		31337,
		0,
		128,
		IPPROTO_TCP,
		0,
		opt.src_ip,
		dst_ip,
		ip_tcp_fp,
		sizeof ip_tcp_fp,
		opt.ln_ctx,
		ln_ip);

	//ip->ip_dst.s_addr = htonl(dst_ip);
	*dport = htons(state->port);
	//libnet_do_checksum(ip_tcp_fp, IPPROTO_TCP, LIBNET_TCP_H + NMAP_FP_TONE_LEN);
	if (net_send(opt.ln_ctx) == 0)
		FILLSBUF(state, dst_ip, IPPROTO_TCP, ip_tcp_fp, 40);
}

/*
 * Extract two bit tuple from a char array
 * Set two bit typle in a char array
 */
#define BF2_GET(ptr, nr)  ((*((char *)ptr + nr / 4) >> ((nr % 4)*2)) & 0x3)
#define BF2_SET(ptr, nr, val)  (*((char *)ptr + nr / 4) |= ((val & 0x3) << (nr%4)*2))
#define FP_TEST_TCP_PTR(fpts, res)	((res) + (fpts)->ofs_test_tcp)
#define FP_TEST_UDP_PTR(fpts, res)	((res) + (fpts)->ofs_test_udp)
#define FP_TEST_SNMP_PTR(fpts, res)	((res) + (fpts)->ofs_test_snmp)
#define FP_TEST_NVT_PTR(fpts, res)	((res) + (fpts)->ofs_test_nvt)

/*
 * Output the gathered FP informations so that the user can add
 * them to the fingerprint database.
 */
void
fp_output(char *results)
{
	int n;
	char *ptr;
	char trans[] = {'?', 'C', 'O', '-'};
	char buf[512];
	
	printf("-----BEGIN THCRUT FINGERPRINT-----\n");
	if (opt.fpts.cat[FP_CAT_TCP].n_tests > 0)
	{
		ptr = FP_TEST_TCP_PTR(&opt.fpts, results);
		for (n = 0; n < opt.fpts.cat[FP_CAT_TCP].n_tests; n++)
			printf("%dT=%c%%", opt.fpts.cat[FP_CAT_TCP].tests[n].port, trans[BF2_GET(ptr, n)]);
		printf("\n");
	}

	if (opt.fpts.cat[FP_CAT_UDP].n_tests > 0)
	{
		ptr = FP_TEST_UDP_PTR(&opt.fpts, results);
		for (n = 0; n < opt.fpts.cat[FP_CAT_UDP].n_tests; n++)
			printf("%dU=%c%%", opt.fpts.cat[FP_CAT_UDP].tests[n].port, trans[BF2_GET(ptr, n)]);
		printf("\n");
	}

	for (n = 0; n < opt.fpts.cat[FP_CAT_BANNER].n_tests; n++)
	{
		ptr = results + opt.fpts.ofs_test_banner + n * FP_BTEST_SZ;
		perlstring(buf, sizeof buf,  ptr, strlen(ptr));
		printf("%dB=\"%s\"\n", opt.fpts.cat[FP_CAT_BANNER].tests[n].port, buf);
	}
	for (n = 0; n < opt.fpts.cat[FP_CAT_WWW].n_tests; n++)
		printf("%dW=\"%s\"\n", opt.fpts.cat[FP_CAT_WWW].tests[n].port, results + opt.fpts.ofs_test_www + n * FP_WTEST_SZ);
	for (n = 0; n < opt.fpts.cat[FP_CAT_SNMP].n_tests; n++)
	{
		ptr = results + opt.fpts.ofs_test_snmp + n * FP_STEST_SZ;
		perlstring(buf, sizeof buf,  ptr, strlen(ptr));
		printf("%dS=\"%s\"\n", opt.fpts.cat[FP_CAT_SNMP].tests[n].port, buf);
	}
	for (n = 0; n < opt.fpts.cat[FP_CAT_NVT].n_tests; n++)
	{
		ptr = results + opt.fpts.ofs_test_nvt + n * FP_NTEST_SZ;
		perlstring(buf, sizeof buf,  ptr, strlen(ptr));
		printf("%dN=\"%s\"\n", opt.fpts.cat[FP_CAT_NVT].tests[n].port, buf);
	}
	printf("-----END THCRUT FINGERPRINT-----\n");
}


#if 0
char *
fp_match_fp2(char *results)
{
	struct _fp *fp = opt.fpts.fps;
	char *ptr;

	/*
	 * Keep variable substitution in mind.
	 * We might have to call this recursively and
	 * jump to other variable-lines (which are like
	 * fp-lines, they contain a number of fp_test's
	 * (0..fp->n_tests
	 */
	while (fp)
	{
		/*
		 * Call a function that returns the accuracy
		 * for given results. (e.g. we pass the results
		 * and get back the accuracy).
		 * We can do this per test and add up the accuracy.
		 */
		/* BANNER */
		/*
		 * FIXME: The problem is that we account this for every
		 * port. e.g. banner on port 80, banner on port 21, ..
		 * And if match on 80 then this does not mean that
		 * we stop with 21 :/
		 * This is what testnr is all about.
		 * Well, we could mark it in an array if we already
		 * have an result for this testnr (e.g store the accuracy in there).
		 */
	//	ptr = results + opt.fpts.ofs_test_banner + testnr * FP_BTEST_SZ;


	}
}
#endif

/*
 * From a state table try to guess the OS.
 * Return string if found and class & accuracy.
 * Return NULL otherwise.
 */
char *
fp_match_fp(unsigned int *ret_class, int *ret_accuracy, char *results)
{
	struct _fp *fp = opt.fpts.fps, *fp_match = NULL;
	struct _fp_test *fpt;
	unsigned char cat;
	unsigned char testnr;
	int accuracy_old = 1, accuracy = 0;
	char *ptr;
	int offsets[99];
	char state_port;
	int n;
	char tcp_open_found;
	int accuracy_tcp;
	char match, match_tcp;
//	int accuracy_idx[128];

//	memset(&accuracy_idx, 0, sizeof accuracy_idx);

	while (fp)
	{
		accuracy = 0;
		accuracy_tcp = 0;
		tcp_open_found = 0;
		for (n = 0; n < fp->n_tests; n++)
		{
			fpt = &fp->fp_tests[n];
		//	if (accuracy_idx[fpt->testnr_cat])
		//		continue;

			cat = FP_TEST_CAT(fpt);
			testnr = FP_TEST_NR(fpt);
			match = 0;
			match_tcp = 0;
			switch (cat)
			{
			case FP_CAT_TCP:
				ptr = FP_TEST_TCP_PTR(&opt.fpts, results);
				state_port = BF2_GET(ptr, testnr);
				/*
				 * If we match OPEN or CLOSED we increase the
				 * accuracy. If the results does not know about
				 * the STATE (== 0b00) we ignore it
				 */
				if (!state_port) /* Dont care */
					break;
				if (state_port & fpt->flags)
				{
					/*
					 * We discard a port state test if
					 * not a single port for which we
					 * test for is found open.
					 */
					if (state_port & FP_TEST_OPEN)
						tcp_open_found = 1;
					match_tcp = 1;
				} else
					accuracy_tcp--;
				break;
			case FP_CAT_UDP:
				ptr = FP_TEST_UDP_PTR(&opt.fpts, results);
				state_port = BF2_GET(ptr, testnr);
				if (!state_port)
					break;
				if (state_port & fpt->flags)
					match = 1;
				else
					accuracy--;
			case FP_CAT_BANNER:
				//fprintf(stderr, "BMATCHING %s\n", fpt->str);
				ptr = results + opt.fpts.ofs_test_banner + testnr * FP_BTEST_SZ;
				if (*ptr == '\0')
					break;
				if (pcre_exec(fpt->pattern, fpt->hints, ptr, strlen(ptr), 0, 0, offsets, sizeof offsets) >= 0)
					match = 1;
				break;
			case FP_CAT_WWW:
				ptr = results + opt.fpts.ofs_test_www + testnr * FP_WTEST_SZ;
				if (*ptr == '\0')
					break;
				if (pcre_exec(fpt->pattern, fpt->hints, ptr, strlen(ptr), 0, 0, offsets, sizeof offsets) >= 0)
					match = 1;
				break;
			case FP_CAT_SNMP:
				ptr = FP_TEST_SNMP_PTR(&opt.fpts, results);
				if (*ptr == '\0')
					break;
				if (pcre_exec(fpt->pattern, fpt->hints, ptr, strlen(ptr), 0, 0, offsets, sizeof offsets) >= 0)
					match = 1;
				break;
			case FP_CAT_NVT:
				ptr = FP_TEST_NVT_PTR(&opt.fpts, results);
				if (*ptr == '\0')
					break;
				if (pcre_exec(fpt->pattern, fpt->hints, ptr, strlen(ptr), 0, 0, offsets, sizeof offsets) >= 0)
					match = 1;
				break;
			default:
				fprintf(stderr, "%s Unknown category (%d)\n", __func__, cat);
			}

			/*
			 * On match (TRUE) increase accuracy.
			 * On !match (FALSE) do nothing here (see above).
			 * Only change value (reset or increment) on MATCH.
			 */
			if (((match) || (match_tcp)) && (fpt->accuracy == 0))
			{
				accuracy = 0;
				accuracy_tcp = 0;
				break;
			}
			if (match)
			{
				accuracy += fpt->accuracy;
				if (accuracy >= 20)
					break;
			}
			if (match_tcp)
			{
				accuracy_tcp += fpt->accuracy;
				if (accuracy_tcp >= 20)
					break;
			}
		} /* this testline */

		/*
		 * We discard the results of a tcp port state test if not a
		 * single port that is checked for state open could be found.
		 */
		if (tcp_open_found)
		{
			tcp_open_found = 0;
			accuracy += accuracy_tcp;
		}

		if (accuracy >= accuracy_old)
		{
			/* FIXME: also store class or ptr here */
			accuracy_old = accuracy;
			fp_match = fp;
			if (accuracy >= 20) /* BAIL OUT! Max value reached */
			{
				accuracy = 20;
				break;
			}
		}

		fp = fp->next;
	}

	if (!fp_match)
		return NULL;

	if (ret_accuracy)
		*ret_accuracy = accuracy_old;
	if (ret_class)
		*ret_class = fp_match->class;

	return opt.fpts.strings + fp_match->ofs_string;
}

/*
 * Called by sender and receiver
 * Outputs all gathered informations.
 */
static void
dis_end(struct _state_fp *state)
{
	long l = htonl(STATE_ip(state));
	struct _nmap_osfp_TONE *tone, *mytone;
	char *ptr;
	unsigned int class;
	int accuracy = 0;
	int n;
	char buf[1024];
	struct _binout *binout = (struct _binout *)buf;
	size_t len;
	int ret;

	/*
	 * Later on we first check port state FP and
	 * compare if NMAP can give us a more (but not less!)
	 * specific result.
	 */
	if (opt.flags & FL_OPT_FP)
	{
		/*
		 * Port State fingerprint
		 */
		ptr = fp_match_fp(&class, &accuracy, state->results);
		tone = (struct _nmap_osfp_TONE *)state->un.ptr;
		if ((!ptr) && (tone) && (!tone->next) && (accuracy == 0))
			ptr = opt.osfp.strings + tone->ofs_string;


		/* Binary output for further processing */
		if (opt.flags & FL_OPT_BINOUT)
		{
			if (class)
			{
				len = sizeof *binout;
				/*
				 * Copy string of fingerprint with the terminating \0.
				 */
				if (ptr)
					len += strlcpy(binout->str, ptr, sizeof buf - sizeof *binout) + 1;

				binout->ip = l;
				binout->class = htonl(class);
				binout->len = htons(len);
				ret = write(1, binout, len);
				if (ret < 0)
					ERREXIT("write() = %d\n", ret);
			}
			/* Otherwise (if no PTR string found) did we already
			 * output this host after discovery
			 */
		} else {
			if (ptr)
			{
				if (opt.flags & FL_OPT_VERBOSE)
					printf("Host: %s %s(%u, %s) %d %s\n", int_ntoa(l), FP_class2str(NULL, class), class, int2bit(class), accuracy, ptr);
				else
					printf("Host: %s %s\n", int_ntoa(l), ptr);
			} else
				printf("Host: %s\n", int_ntoa(l));
		}

		/*
		 * NMAP
		 * For each FP line check if any testnr line matches
		 *
		 * FIXME: NMAP is currently EXPERIMENTAL. the NMAP OS FP file
		 * requies class informations. With this we can precise our FP
		 * results or select a OS from NMAP if all os-values are
		 * equal (same os).
		 *
		 * Have to convince Fyodor to cathegorze nmap-of-fingerprints.
		 */
		if ((tone) && (opt.flags & FL_OPT_VERBOSE))
		{
			tone = (struct _nmap_osfp_TONE *)state->un.ptr;
			mytone = tone;
			n = 1;
			printf("%03d NMAP: %s:%ld:\"%s\"\n", n++, int_ntoa(l), tone->class, opt.osfp.strings + tone->ofs_string);
			while ( (tone = tone->next))
			{
				if (!NMAP_TONE_MATCH(tone, mytone->wsize, NMAP_DF_ISSET(mytone), tone->ops))
					continue;
				printf("%03d NMAP: %d, %x, %s\n", n++, NMAP_DF_ISSET(tone)?1:0, tone->wsize, opt.osfp.strings + tone->ofs_string);
			}
		}

		/* Output all gathere information for debugging purposes */
		if ((opt.flags & FL_OPT_VERBOSE) || (!ptr))
			fp_output(state->results);

	} else if (opt.flags & FL_OPT_HOSTDISCOVERY) {
		if (opt.flags & FL_OPT_BINOUT)
		{
			ret = write(1, &l, 4);
		} else {
			printf("Host: %s\n", int_ntoa(l));
		}
	}

	STATE_reset(state);
}

#define PACKET_ALIGN(buf, len, min, max, p, packet) do{ \
	if ((p->caplen < opt.dlt_len) || (p->caplen - opt.dlt_len < min)) \
		return; \
	if (p->caplen - opt.dlt_len < max) \
		len = p->caplen - opt.dlt_len; \
	else \
		len = max; \
	memcpy(buf, packet + opt.dlt_len, len); \
}while(0)

/*
 * Dummy, to prevent racecondition if sender times this scan out
 * but it's still looked up by pcap thread.
 */
static void
dis_recvdummy(struct _state_fp *state, struct pcap_pkthdr *p, uint8_t *packet)
{
}

/*
 * Discovery found the host.
 * Now we never reset the state to 0 but always go via dis_end
 * to output the found IP after FP has completed.
 *
 * Save open tcp port here if found one.
 */
static void
dis_recv(struct _state_fp *state, struct pcap_pkthdr *p, uint8_t *packet)
{
	char buf[256];
	size_t len;
	struct ip *ip = (struct ip *)buf;
	struct tcphdr *tcp;
	struct udphdr *udp;
	unsigned short options;
	char *ptr;
	uint8_t *udp_data;
	uint8_t *udp_end;
	unsigned char asn_type;

	PACKET_ALIGN(buf, len, 40, sizeof buf, p, packet);
	if (vrfy_ip(ip, len, &options) != 0)
		return;
	if ((ip->ip_p == IPPROTO_TCP) && (len < 40 + options))
		return;
	else if (len < 28 + options) /* UDP / min ICMP header */
		return;

	tcp = (struct tcphdr *)(buf + 20 + options);

	/*
	 * If we are in discovery mode any packet from the remote is
	 * fine.
	 */
	if (STATE_current(state) <= STATE_DISCOVERY_MAX)
	{
		if ((opt.flags & FL_OPT_FP) && (ip->ip_p == IPPROTO_TCP) && (len >= 40 + options))
		{
			if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
				state->flags |= STATE_FOUND_OPEN_PORT;

			state->port = ntohs(tcp->th_sport);
		}

		/* Discovery ended */
		STATE_reschedule(state, 1); /* Why here? dis_end_dis() might start a job */
		dis_end_dis(state);
		return;
	}

	if (ip->ip_p == IPPROTO_UDP)
	{
		if (!opt.fpts.cat[state->cat].n_tests)
			return;
		udp = (struct udphdr *)(buf + 20 + options);
		if (ntohs(udp->uh_sport) != opt.fpts.cat[state->cat].tests[state->testnr].port)
			return;

		if (state->cat == FP_CAT_UDP)
		{
			ptr = FP_TEST_UDP_PTR(&opt.fpts, state->results);
			BF2_SET(ptr, state->testnr, FP_TEST_OPEN);
		} else if (state->cat == FP_CAT_SNMP) {
			udp_data = (uint8_t *)udp + 8;
			udp_end = udp_data + len - 20 - options - 8;
			/* VERSION */
			if (!(len = ASN_next(&udp_data, udp_end - udp_data, &asn_type)))
				return;
			udp_data += len;
			/* COMMUNITY */
			if (!(len = ASN_next(&udp_data, udp_end - udp_data, &asn_type)))
				return;
			udp_data += len;
			/* Now until next string */
			while (1)
			{
				len = ASN_next(&udp_data, udp_end - udp_data, &asn_type);
				if (!len)
					return;
				if (asn_type == ASN_OCTET_STR)
					break;
				udp_data += len;
			}
			if (len > FP_STEST_SZ - 1)
				len = FP_STEST_SZ - 1;
			ptr = FP_TEST_SNMP_PTR(&opt.fpts, state->results);
			memcpy(ptr, udp_data, len);
			ptr[len] = '\0';
		}
		goto endfp;
	}

	if ((ip->ip_p != IPPROTO_TCP) || (!opt.fpts.cat[FP_CAT_TCP].n_tests))
		return;

	if (ntohs(tcp->th_sport) != opt.fpts.cat[FP_CAT_TCP].tests[state->testnr].port)
			return;

	ptr = FP_TEST_TCP_PTR(&opt.fpts, state->results);
	if ((tcp->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
	{
		BF2_SET(ptr, state->testnr, FP_TEST_OPEN);
		if (!(state->flags & STATE_FOUND_OPEN_PORT))
		{
			state->flags |= STATE_FOUND_OPEN_PORT;
			state->port = ntohs(tcp->th_sport);
		}
	} else
		BF2_SET(ptr, state->testnr, FP_TEST_CLOSED);
endfp:
	if (fp_state_next_switch(state) != 0)
	{
		STATE_reschedule(state, 1);
		dis_end_fp(state);
		return;
	}
}


/*
 * Received FP information.
 */
static void
dis_recvfpI(struct _state_fp *state, struct pcap_pkthdr *p, uint8_t *packet)
{
	char buf[60];
	size_t len;
	struct ip *ip = (struct ip *)buf;
	struct tcphdr *tcp;
	unsigned short ip_options;
	unsigned short tcp_options;
	unsigned long ops;
	//struct _nmap_osfp_TONE *tone;
	char df;
	char opstr[16];

	PACKET_ALIGN(buf, len, 40, 60, p, packet);
	if (ip->ip_p != IPPROTO_TCP)
		return;
	if (vrfy_ip(ip, len, &ip_options) != 0)
		return;
	tcp = (struct tcphdr *)(buf + 20 + ip_options);

	if (vrfy_tcp(tcp, len - 20 - ip_options, &tcp_options) != 0)
		return;

	if (ntohs(tcp->th_dport) != opt.src_port + 1)
		return;

	/* If we got a packet back which is not SYN then
	 * try another port
	 */
	if ((tcp->th_flags & (TH_SYN | TH_ACK)) != (TH_SYN | TH_ACK))
	{
		if (ntohs(tcp->th_sport) == state->port)
		{
			state->flags &= ~STATE_FOUND_OPEN_PORT; /* Not open anymore :/ */
			STATE_reschedule(state, 1); /* RST, start again */
			STATE_current(state) = 0;
			dis_sendfpI(state, NULL); /* No syn back? Service died!? */
		}
		return;
	}

	df = (ip->ip_off & htons(IP_DF)) == 0 ? 0 : 1;

	ops = NMAP_tcpops2ops(opstr, (char *)buf + 40 + ip_options, tcp_options);
	if (ops == -1)
		return;
	state->un.ptr = NMAP_lookup(&opt.osfp, ntohs(tcp->th_win), df, ops);
#if 0
	if (state->un.ptr)
		printf("FP for %s, wsize %x, df %d, ops: %s %ld\n", int_ntoa(STATE_ip(state)), (unsigned short)ntohs(tcp->th_win), df, opstr, ops);
#endif
	
	dis_end_nmapfp(state);
}


void
scanner_filter(unsigned char *u, struct pcap_pkthdr *p, unsigned char *packet)
{
	struct _state *state;
	unsigned long l;

	//DEBUGF("filter invoked %u, %u, dltlen: %d\n", p->caplen, p->len, opt.dlt_len);
	/* The RFC says that ETH frame must have a min. length of 64 bytes.
	 * Tailers are truncated by pcap lib and we might get less here.
	 */
	if (p->caplen < (opt.dlt_len + 20))
		return;

	memcpy(&l, packet + opt.dlt_len + 12, 4);
	if (!(state = STATE_by_ip(&opt.sq, ntohl(l))))
		return;

	state->reschedule = 0;
	/* FIXME: we can also do the state switch here.
	 * No need for idspatcher functions.
	 * - get IP header + options
	 * - pass payload (unaligned) + ip header.
	 */
	if (state->current < sizeof dispatch_funcs / sizeof *dispatch_funcs)
		dispatch_funcs[state->current]((struct _state_fp *)state, p, packet);
}

