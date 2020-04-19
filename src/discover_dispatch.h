/*
 * $Id: discover_dispatch.h,v 1.4 2003/05/16 08:58:45 skyper Exp $
 */

#ifndef __THCRUT_SCANNER_DISPATCH_H__
#define __THCRUT_SCANNER_DISPATCH_H__ 1

#include <pcap.h>
#include "state.h"

/*
 * The raw socket might overrun if the local network is scanned.
 * This is due to arp resolving and a too small kernel buffer. 
 * We buffer the packets in userland if this happens. The buffer
 * is checked and flushed before any state is processed.
 * 
 * FIXME: was passiert wenn im letzten state? return er da nicht
 * automatisch oder deleted den state?
 * Ist alles unabhaengig von state. sprich state koennte schon auf ende
 * sein obwohl noch was im send buffer ist :/
 */

/*
 * Discovery without FP requires a 40 byte send buffer.
 * slen == 0: no buffered data, continue.
 */
struct _state_dis
{
	struct _state state;
	unsigned short slen;
	char sbuf[20 + 20 + FP_MAX_LEN];  /* Does not need to be that large. */
					  /* Rather small packets are send   */
					  /* in discoveyr only phase. ICMP   */
					  /* is the max.                     */
};

/*
 * FP discovery sends at a max. 60 bytes.
 */
struct _state_fp
{
	struct _state state;
	unsigned short slen;
	char sbuf[20 + 20 + FP_MAX_LEN];      /* send buffer */

	union _un
	{
		void *ptr;  /* NMAP results */
		char turn;  /* Turn         */
	} un;
	int sox; /* fixme: this only needs to be 10 bits */
	unsigned short port;  /* tcp, HBO */
	unsigned char flags;
	unsigned char testnr:5; /* number in that category           */
	unsigned char cat:3;    /* category: TCP, UDP, Banner or WWW */
	char results[0];
};

/*
 * Binary output format
 */
struct _binout
{
	unsigned short len;
	unsigned short reserved;
	unsigned int ip;
	unsigned int class;
	char str[0];
};

#define STATE_FOUND_OPEN_PORT   (0x01)
#define STATE_CRLF_SENT		(0x02)

void dis_timeout(struct _state *state);
void scanner_filter(unsigned char *u, struct pcap_pkthdr *p, unsigned char *packet);

#endif /* !__THCRUT_SCANNER_DISPATCH_H__ */
