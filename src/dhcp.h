/* 
 * THC-rut
 *
 * DHCP options (and rarp, bootp also...)
 * anonymous@segfault.net
 */

#ifndef THCRUT_DHCP_H
#define THCRUT_DHCP_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* RFC 1497 Vendor Extensions */

#define DHCP_PAD        0
#define DHCP_SUBMASK    1
#define DHCP_TIMEOFF    2
#define DHCP_ROUTER     3
#define DHCP_TSERV      4
#define DHCP_NS         5
#define DHCP_DNS        6
#define DHCP_LOGSERV    7
#define DHCP_COOKSERV   8
#define DHCP_LPRSERV    9
#define DHCP_IMPRSERV   10
#define DHCP_RLSERV     11
#define DHCP_HOSTNAME   12
#define DHCP_BOOTFSZ    13
#define DHCP_COREFILE   14
#define DHCP_DOMAIN     15
#define DHCP_SWAPSERV   16
#define DHCP_ROOTPATH   17
#define DHCP_EXTPATH    18

/* IP Layer Parameters per Host */

#define DHCP_IPFRWD     19
#define DHCP_NLSR       20
#define DHCP_PFILTER    21
#define DHCP_MAXDGRASM  22
#define DHCP_IPTTL      23
#define DHCP_PMTUTOUT   24
#define DHCP_PMTUTBL    25

/* IP Layer Parameters per Interface */

#define DHCP_MTU        26
#define DHCP_LSUBNET    27
#define DHCP_BCAST      28
#define DHCP_MASKDISC   29
#define DHCP_MASKSUPP   30
#define DHCP_ROUTDISC   31
#define DHCP_ROUTSOL    32
#define DHCP_STATROUTES 33

/* Link Layer Parameters per Interface */

#define DHCP_TRENCAP    34
#define DHCP_ARPCACHET  35
#define DHCP_ETHENC     36

/* IP Layer Parameters per Host */

#define DHCP_IPFRWD     19
#define DHCP_NLSR       20
#define DHCP_PFILTER    21
#define DHCP_MAXDGRASM  22
#define DHCP_IPTTL      23
#define DHCP_PMTUTOUT   24
#define DHCP_PMTUTBL    25

/* IP Layer Parameters per Interface */

#define DHCP_MTU        26
#define DHCP_LSUBNET    27
#define DHCP_BCAST      28
#define DHCP_MASKDISC   29
#define DHCP_MASKSUPP   30
#define DHCP_ROUTDISC   31
#define DHCP_ROUTSOL    32
#define DHCP_STATROUTES 33

/* Link Layer Parameters per Interface */

#define DHCP_TRENCAP    34
#define DHCP_ARPCACHET  35
#define DHCP_ETHENC     36

/* TCP Parameters */

#define DHCP_TCPTTL     37
#define DHCP_TCPKEEPA   38
#define DHCP_TCPKEEPG   39

/* Application and Service Parameters */

#define DHCP_NISDOM     40
#define DHCP_NISSERV    41
#define DHCP_NTP        42
#define DHCP_VENDOR     43
#define DHCP_NBNS       44
#define DHCP_NBDD       45
#define DHCP_NBNODE     46
#define DHCP_NBSCOPE    47
#define DHCP_XFONTSERV  48
#define DHCP_XDISMANAG  49

/* DHCP Extensions */

#define DHCP_REQIP      50
#define DHCP_IPLEASET   51
#define DHCP_OVERLOAD   52
#define DHCP_MSGTYPE    53
#define DHCP_SERVERID   54
#define DHCP_PARAMREQ   55
#define DHCP_MSG        56
#define DHCP_MAXMAGSZ   57
#define DHCP_RENTIME    58
#define DHCP_REBTIME    59
#define DHCP_CLASSID    60
#define DHCP_CLIENTID   61

#define DHCP_END        255
#define DHCP_MAXTAG     61

#define DHCP_MAGICCOOKIE         "\x63\x82\x53\x63"
#define DHCP_MIN_OPT        312

#define DHCP_NONE       0x00    /* no value/unsupported, skip this ! */
#define DHCP_IPV4       0x01    /* a.b.c.d */
#define DHCP_ASCII      0x02    /* ASCII string */
#define DHCP_8I         0x03    /* 8 bit signed int */
#define DHCP_8UI        0x04    /* 8 bit unisgned int */
#define DHCP_16I        0x05    /* 16 bit signed int */
#define DHCP_16UI       0x06    /* 16 bit unsigned int */
#define DHCP_32I        0x07    /* 32 bit signed int */
#define DHCP_32UI       0x08    /* 32 bit unsigned int */
#define DHCP_HEX        0x09    /* hex string */
#define DHCP_MAC        0x0a    /* MAC-style: 12:ab:de:ad:be:ef:...? */
#define DHCP_BOOL       0x0b    /* 1='true', 0='false' */
#define DHCP_1HEX       0x0c    /* _one_ hex char */
#define DHCP_32TIME     0x0d    /* time in seconds, 4 bytes */

#define DHCP_TYPEMASK    0x1f    /* this mask DHCP_<type> from options */
/* 3 options possible: 0x20 0x40 0x80 */
#define DHCP_MULTI      0x80    /* list of values, like DHCP_ROUTER etc */

#define BOOTP_REQUEST   1
#define BOOTP_REPLY     2

#define BOOTPVENEXT_H   64      /* lenght of bootp vendor extension */

#ifndef int_ntoa
#define int_ntoa(x)   inet_ntoa(*((struct in_addr *)&(x)))
#endif

struct _dhcpnfoset
{
    unsigned char  tag;
    unsigned char  enctype;     /* encoding type, DHCP_8I, DHCP_HEX, ... */
    unsigned char  *name;
};

struct _dhcpset
{
    unsigned char *sptr;    /* start pointer to the dhcp-option array. fix */
    unsigned char *lptr;    /* last ptr */
    unsigned long size;     /* overall size of the entire buffer sptr */
    unsigned long lsize;    /* size of currently used space. (sptr - lptr) */
    unsigned char *lastsub; /* pointer to last suboption field */
};

/*
 * we can use this struct as header template (everything is 4 byte aligned,
 * no struct-gabs in here. good.
 * the 64 byte vendor extension is MISSING here. this is JUST the bootp header.
 */
struct _bootp
{
    unsigned char      op;         /* req;*/
    unsigned char      htype;      /* 1 = 10mbit */
    unsigned char      hlen;       /* ethernet = 6 */
    unsigned char      hops;       /* 0 */
    unsigned long      xid;        /* xid from client, should be != 0 */
    unsigned short     secs;       /* 0 (?) */
    unsigned short     flags;      /* [B| MBZ ] */
    unsigned int       ciaddr;     /* */
    unsigned int       yiaddr;     /* <- ip address offered to client */
    unsigned int       siaddr;     /* ip address of next bootstrap server */
    unsigned int       giaddr;     /* 0 */
    unsigned char      chaddr[16]; /* chaddr from client DHCPDISCOVER */
    char        sname[4*16];/* Server host name or options */
    char        file[8*16]; /* Client boot file name or options */
    char	options[0];
};

const char *dhcp_str(unsigned char);
int init_dhcpset(struct _dhcpset *, unsigned char *, unsigned long len);
int dhcp_add_option(struct _dhcpset *, unsigned char tag, unsigned char len, unsigned char *value);
int dhcp_add_suboption(struct _dhcpset *, unsigned char);
int build_bootp(char *, unsigned char *, int);
char *dhcp_val2str(char *, int, unsigned char, unsigned char, unsigned char *);
struct _dhcpnfoset *dhcp_getnfoset(void);
void dhcp_set_default(struct _dhcpset *ds);

#endif /* !THCRUT_DHCP_H */
