#ifndef __THCRUT_THCRUT_H__
#define __THCRUT_THCRUT_H__ 1

#include <sys/types.h>
#include <unistd.h>
#include <pcap.h>
#include <libnet.h>
#include "state.h"
#include "nmap_compat.h"
#include "fp.h"
#include "range.h"

#define BOOTP_PLEN		(308)
#define MAX_PAYLOAD_SIZE	(1024)
#define ETHDLTLEN		(14)
#define PCAP_FILTER 		"arp or icmp or udp"
#define ETHBCAST		"\xff\xff\xff\xff\xff\xff"
#define ETHZCAST		"\x00\x00\x00\x00\x00\x00"


/*
 * this is already defined on hpux and *bsd.
 * The syntax is nearly posix - no problem to use the system wide MIN macro
 */
#ifndef MIN
# define MIN(a,b)    ((a)<(b)?(a):(b))
#endif

struct _spfmac
{
    u_char  mac[6];
    int     prfxlen;
};

struct _spfip
{
    u_long  addr;
};

struct _opt
{
	pcap_t *ip_socket;
	int dlt_len;
	long hosts_parallel; /* how many hosts at the same time */
	char *device;
	long net;   /* network address in HBO */
	long bcast; /* broadcast address in HBO */
	int src_ip; /* NBO */
	int dst_ip;
	unsigned short src_port;
	unsigned short ip_id;  /* IP id field we sniff for */
	char *macrangestr;
	struct libnet_link_int  *network;
	unsigned int flags;
	char **argvlist;
	int argc;
	pid_t childpid;
	struct _ipranges ipr;
	struct _state_queue sq;
	int rawsox;
	struct _nmap_osfp osfp;
	struct _fp_testsuite fpts;
};
#if 0
#define OPT_RARP            0x01
#define OPT_BOOTP           0x02
#define OPT_DHCP            0x04
#define OPT_ICMPADDR        0x08
#define OPT_ICMPPING        0x10
#define OPT_ARPD            0x20
#define OPT_BARP            0x40
#define OPT_ICMPRS		(0x80)
#endif
#define FL_OPT_HOSTDISCOVERY	(0x100)
#define FL_OPT_FP		(0x200)
#define FL_OPT_VERBOSE		(0x400)
#define FL_OPT_SPOOFMAC		(0x800)
#define FL_OPT_BINOUT		(0x1000)
#define FL_OPT_SPREADMODE	(0x2000)


struct _lnet
{
	char err_buf[LIBNET_ERRBUF_SIZE];   /* error buffer */
	u_char *packet;                     /* pointer to our packet buffer */
	int packet_size;
	u_char payload[MAX_PAYLOAD_SIZE];
};

struct Ether_header
{
    uint8_t ether_dhost[ETH_ALEN];
    uint8_t ether_shost[ETH_ALEN];
    uint16_t ether_type;
};

#define ETH_ARP_H   28
/*
 * we store Arp info in here only. we cannot just match the pointer
 * of this structure to the u_char packet field from pcap.
 * (struct variable alignment).
 */
struct Arpnfo
{
    unsigned short ar_op;   /* ARP opcode (command).  */
    unsigned char *ar_sha; /* Sender hardware address.  */
    unsigned int ar_sip;    /* Sender IP address.  */
    unsigned char *ar_tha; /* Target hardware address.  */
    unsigned int ar_tip;    /* Target IP address.  */
};

struct ETH_arp
{
	short hw_type;
	short p_type;
	unsigned char hw_size;
	unsigned char p_size;
	short ar_op;
	char ar_sha[ETH_ALEN];
	char ar_sip[4];
	char ar_tha[ETH_ALEN];
	char ar_tip[4];
};

void die(int, char *, ...);
void start_arpd();
void sig_waitchld(int);
void do_signal(int);
int handle_ip(u_char *, int);
int handle_arp(u_char *, int);
int list_dhcp();
#if 0
int init_next_macip(char *str, struct _bmac *bmac, struct _bip *bip, char *defaultmac);
#endif
int build_llip(char *mac, char proto, int iplen, long sip, long dip);

#endif  /* !__THCRUT_THCRUT_H__ */

