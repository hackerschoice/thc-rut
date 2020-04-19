/*
 * $Id: thcrut_pcap.h,v 1.3 2003/05/25 18:19:16 skyper Exp $
 */

#ifndef __THCRUT_PCAP_H__
#define __THCRUT_PCAP_H__ 1

#include <pcap.h>

#if 0
struct _pcap
{
	char err_buf[PCAP_ERRBUF_SIZE];
	pcap_t  *ip_socket;
};
#endif

#define PCAPBUFSIZE		(1024)

pcap_t *init_pcap(char *device, int promisc, char *filter, long *net, long *bcast, int *dltlen);
int tr_pcap_fileno(void);
void tr_pcap_dispatch(pcap_handler callback);
int thcrut_pcap_stats(pcap_t *p, struct pcap_stat *ps);

#endif /* !__THCRUT_PCAP_H__ */
