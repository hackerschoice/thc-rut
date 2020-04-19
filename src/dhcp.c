#include "default.h"
#include "dhcp.h"


static struct _dhcpnfoset dhcpnfo[] = {

/* RFC 1497 Vendor Extensions */

    {DHCP_PAD       , DHCP_NONE, ""},
    {DHCP_SUBMASK   , DHCP_IPV4, "Subnet Mask"},
    {DHCP_TIMEOFF   , DHCP_32TIME, "Time Offset"},
    {DHCP_ROUTER    , (DHCP_IPV4|DHCP_MULTI), "Router"},
    {DHCP_TSERV     , (DHCP_IPV4|DHCP_MULTI), "Time Server"},
    {DHCP_NS        , (DHCP_IPV4|DHCP_MULTI), "Name Server"},
    {DHCP_DNS       , (DHCP_IPV4|DHCP_MULTI), "Domain Name Server"},
    {DHCP_LOGSERV   , (DHCP_IPV4|DHCP_MULTI), "Log Server"},
    {DHCP_COOKSERV  , (DHCP_IPV4|DHCP_MULTI), "Cookie Server"},
    {DHCP_LPRSERV   , (DHCP_IPV4|DHCP_MULTI), "LPR Server"},
    {DHCP_IMPRSERV  , (DHCP_IPV4|DHCP_MULTI), "Impress Server"},
    {DHCP_RLSERV    , (DHCP_IPV4|DHCP_MULTI), "Resource Location Server"},
    {DHCP_HOSTNAME  , DHCP_ASCII, "Host Name"},
    {DHCP_BOOTFSZ   , DHCP_16UI, "Boot File Size"},
    {DHCP_COREFILE  , DHCP_ASCII, "Merit Dump File"},
    {DHCP_DOMAIN    , DHCP_ASCII, "Domain Name"},
    {DHCP_SWAPSERV  , DHCP_IPV4, "Swap Server"},
    {DHCP_ROOTPATH  , DHCP_ASCII, "Root Path"},
    {DHCP_EXTPATH   , DHCP_ASCII, "Extensions Path"},

/* IP Layer Parameters per Host */

    {DHCP_IPFRWD    , DHCP_BOOL, "IP Forwarding"},
    {DHCP_NLSR      , DHCP_BOOL, "Non-Local Source Routing"},
    {DHCP_PFILTER   , (DHCP_IPV4|DHCP_MULTI), "Policy Filter Optioin"},
    {DHCP_MAXDGRASM , DHCP_16UI, "Maximum Datagram Reassembly Size"},
    {DHCP_IPTTL     , DHCP_8UI, "Default IP Time-to-Live"},
    {DHCP_PMTUTOUT  , DHCP_32TIME, "Path MTU Aging Timeout"},
    {DHCP_PMTUTBL   , (DHCP_16UI|DHCP_MULTI), "Path MTU Plateau Table"},

/* IP Layer Parameters per Interface */

    {DHCP_MTU       , DHCP_16UI, "Interface MTU Option"},
    {DHCP_LSUBNET   , DHCP_BOOL, "All Subnets are Local"},
    {DHCP_BCAST     , DHCP_IPV4, "Broadcast Address"},
    {DHCP_MASKDISC  , DHCP_BOOL, "Perform Mask Discovery"},
    {DHCP_MASKSUPP  , DHCP_BOOL, "Mask Supplier Option"},
    {DHCP_ROUTDISC  , DHCP_BOOL, "Perform Router Discovery"},
    {DHCP_ROUTSOL   , DHCP_IPV4, "Router Solicitation Address"},
    {DHCP_STATROUTES, (DHCP_IPV4|DHCP_MULTI), "Static Route"},

/* Link Layer Parameters per Interface */

    {DHCP_TRENCAP   , DHCP_BOOL, "Trailer Encapsulation"},
    {DHCP_ARPCACHET , DHCP_32TIME, "ARP Cache Timeout"},
    {DHCP_ETHENC    , DHCP_BOOL, "Ethernet Encapsulation"},

/* TCP Parameters */

    {DHCP_TCPTTL    , DHCP_8UI, "TCP Default TTL"},
    {DHCP_TCPKEEPA  , DHCP_32TIME, "TCP Keepalive Interval"},
    {DHCP_TCPKEEPG  , DHCP_BOOL, "TCP Keepalive Garbage"},

/* Application and Service Parameters */

    {DHCP_NISDOM    , DHCP_ASCII, "NIS Domain"},
    {DHCP_NISSERV   , (DHCP_IPV4|DHCP_MULTI), "NIS Servers"},
    {DHCP_NTP       , (DHCP_IPV4|DHCP_MULTI), "NTP Servers"},
    {DHCP_VENDOR    , DHCP_HEX, "Vendor Specific Information"},
    {DHCP_NBNS      , (DHCP_IPV4|DHCP_MULTI), "NetBIOS over TCP/IP Name Server"},
    {DHCP_NBDD      , (DHCP_IPV4|DHCP_MULTI), "NetBIOS over TCP/IP Datagram Distribution Server"},
    {DHCP_NBNODE    , DHCP_1HEX, "NetBIOS over TCP/IP Node Type"},
    {DHCP_NBSCOPE   , DHCP_HEX, "NetBIOS over TCP/IP Scope"},
    {DHCP_XFONTSERV , (DHCP_IPV4|DHCP_MULTI), "X Window System Font Server"},
    {DHCP_XDISMANAG , (DHCP_IPV4|DHCP_MULTI),"X Window System Display Manager"},
    
/* DHCP Extensions */

    {DHCP_REQIP     , DHCP_IPV4, "Requested IP Address"},
    {DHCP_IPLEASET  , DHCP_32TIME, "IP Address Lease Time"},
    {DHCP_OVERLOAD  , DHCP_1HEX, "Overload"},
    {DHCP_MSGTYPE   , DHCP_1HEX, "DHCP Message Type"},
    {DHCP_SERVERID  , DHCP_IPV4, "Server Identifier"},
    {DHCP_PARAMREQ  , DHCP_HEX, "Parameter Request List"},
    {DHCP_MSG       , DHCP_ASCII, "Message"},
    {DHCP_MAXMAGSZ  , DHCP_16UI, "Maximum DHCP Message Size"},
    {DHCP_RENTIME   , DHCP_32TIME, "Renewal (T1) Time Value"},
    {DHCP_REBTIME   , DHCP_32TIME, "Rebinding (T2) Time Value"},
    {DHCP_CLASSID   , DHCP_HEX, "Class-identifier"},
    {DHCP_CLIENTID  , DHCP_HEX, "Client-identifier"},

/* EO struct */
    
    {DHCP_END       , DHCP_NONE, "DHCP END MARK"},
    {0              , DHCP_NONE, NULL}
};

/*
 * assign the complete set of all dhcp option to dfs.
 * return 0 on success.
 */
struct _dhcpnfoset *
dhcp_getnfoset(void)
{
	return dhcpnfo;
}

/*
 * input: DHCP tag number 0..255
 * returns DHCP tag constant string
 * this function is reentrant.
 */
const char *
dhcp_str(unsigned char tag)
{
    if (tag <= DHCP_MAXTAG)
        return dhcpnfo[tag].name;
    if (tag == DHCP_END)
        return "";

    return "<unknown DHCP tag>";
}


    
/*
 * add a dhcp-option to the array buf
 * return 0 on success
 * if values == NULL, we set the tag + len field but dont 
 * increase the pointer by len. 
 */
int
dhcp_add_option(struct _dhcpset *ds, unsigned char tag, unsigned char len, unsigned char *value)
{

    if (ds->size < ds->lsize+len+2 )
        return -1;

    /* if this is a suboption...save a pointer to this location */
    if (tag == DHCP_PARAMREQ)
    {
        ds->lastsub = ds->lptr;
        len = 0;
        value = NULL;
    }

    memset(ds->lptr++, tag, 1);
    ds->lsize++;
    if (tag == DHCP_END)
        return 0;

    memset(ds->lptr++, len, 1);
    ds->lsize++;
    /* if it was a PARAMREQ, then value == NULL anyway */
    if (value != NULL) 
    {
        memcpy(ds->lptr, value, len);
        ds->lptr += len;
        ds->lsize += len;
    }

    return 0;
}

/*
 * see dhcp_add_option
 * return 0, value gets added for sure...even if 0
 */
int
dhcp_add_suboption(struct _dhcpset *ds, unsigned char value)
{

    if (ds->size < ds->lsize+1 )
        return -1;

    /* increment the suboption counter by +1 each time we add a suboption */
    if (ds->lastsub != NULL)
        *(ds->lastsub + 1) = *(ds->lastsub + 1) + 1;

    memset(ds->lptr++, value, 1);
    ds->lsize++;

    return 0;
}

int
build_bootp(char *ptr, unsigned char *chaddr, int clen)
{
    struct _bootp bp;

    memset(&bp, 0, sizeof(bp));
    bp.op = BOOTP_REQUEST;
    bp.htype    = 1;
    bp.hlen = 6;
    bp.xid = rand();
    bp.secs = htons(9);        /* we try to boot since x seconds */
    if (clen > sizeof(bp.chaddr))
        clen = sizeof(bp.chaddr);
    if (chaddr != NULL)
        memcpy(bp.chaddr, chaddr, clen);
    memcpy(ptr, &bp, sizeof(bp));

    return 0;
}

/*
 * initialize a dhcp option set
 * JUST the OPTIONS..not the header.
 * Magic-cookie is _part_ of the options
 * we also set the MAGICCOOKIE here coz its always mandatory
 */
int
init_dhcpset(struct _dhcpset *ds, unsigned char *ptr, unsigned long len)
{
    ds->sptr = ptr;
    ds->lptr = ptr;
    ds->size = len;
    ds->lsize = 4;
    memcpy(ds->lptr, DHCP_MAGICCOOKIE, 4);
    ds->lptr += 4;

    /* 3 bytes MSGTYPE */
    dhcp_add_option(ds, DHCP_MSGTYPE, 1, "\x01");
    /* 2 bytes PARAMREQ */
    dhcp_add_option(ds, DHCP_PARAMREQ, 0, NULL);

    return 0;
}

static int
dp_dec32UI(char *dbuf, int bs, char *val, unsigned char usz)
{
    snprintf(dbuf, bs, "%lu", (unsigned long)ntohl(*(unsigned long *)val));

    return 0;
}

static int
dp_dec32I(char *dbuf, int bs, char *val, unsigned char usz)
{
    snprintf(dbuf, bs, "%ld", (long)ntohl(*(long *)val));

    return 0;
}

static int
dp_dec16UI(char *dbuf, int bs, char *val, unsigned char usz)
{
    snprintf(dbuf, bs, "%u", (unsigned short)ntohs(*(unsigned short *)val));

    return 0;
}

static int
dp_dec16I(char *dbuf, int bs, char *val, unsigned char usz)
{
    snprintf(dbuf, bs, "%u", (short)ntohs(*(short *)val));

    return 0;
}

static int
dp_dec8UI(char *dbuf, int bs, char *val, unsigned char usz)
{
    snprintf(dbuf, bs, "%u", (unsigned char)*val);

    return 0;
}

static int
dp_dec8I(char *dbuf, int bs, char *val, unsigned char usz)
{
    snprintf(dbuf, bs, "%d", (char)*val);

    return 0;
}

static int
dp_decASCII(char *dbuf, int bs, char *val, unsigned char usz)
{
    int c = 0;
    const char  trans[] =
                "................................ !\"#$%&'()*+,-./0123456789"
                ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
                "nopqrstuvwxyz{|}~...................................."
                "....................................................."
                "........................................";

    while (c++ < usz)
        *dbuf++ = trans[(unsigned char)*val++];

    return 0;
}

static int
dp_decIPV4(char *dbuf, int bs, char *val, unsigned char usz)
{
    snprintf(dbuf, bs, "%s", int_ntoa(*(unsigned long *)(val)));

    return 0;
}

static int
dp_dec32TIME(char *dbuf, int bs, char *val, unsigned char usz)
{
    unsigned char day=0, hour=0, min=0, sec=0;
    unsigned long l = (unsigned long)ntohl(*(unsigned long *)val);

    sec = l % 60;
    l = l / 60;
    min = l % 60;
    l = l / 60;
    hour = l % 24;
    day = l / 24;
    
    if (day != 0)
        snprintf(dbuf, bs, "%u days ", day);
    if (hour != 0)
        snprintf(dbuf+strlen(dbuf), bs, "%u hours ", hour);
    if (min != 0)
        snprintf(dbuf+strlen(dbuf), bs, "%u minutes ", min);
    if (sec != 0)
        snprintf(dbuf+strlen(dbuf), bs, "%u seconds ", sec);

    return 0;
}


static int
dp_decHEX(char *dbuf, int bs, char *val, unsigned char usz)
{
    int i = 0, slen = 0;
    unsigned char c;
    char        hex[] = "0123456789abcdef";

    while (i++ < usz)
    {
        c = *val++;
        if (slen + 3 < bs)
        {
 //           *dbuf++ = ' ';
            *dbuf++ = hex[c / 16];
            *dbuf++ = hex[c % 16];
            slen += 3;
         } else {
                return -1;
        }
    }

    return 0;
}

static int
dp_decBOOL(char *dbuf, int bs, char *val, unsigned char usz)
{

    if (*val == 0)
        snprintf(dbuf, bs, "false(%d)", (unsigned char)*val);
    else
        snprintf(dbuf, bs, "true(%d)", (unsigned char)*val);

    return 0;
}

static int
dp_decMAC(char *dbuf, int bs, char *val, unsigned char usz)
{
    int i = 0, slen = 0;
    unsigned char c;
    char        hex[] = "0123456789abcdef";

    while (i++ < usz)
    {
        c = *val++;
        if (slen + 3 < bs)
        {
            *dbuf++ = hex[c / 16];
            *dbuf++ = hex[c % 16];
            *dbuf++ = ':';
            slen += 3;
         } else {
                return -1;
        }
    }
    *(dbuf-1) = '\0';   /* remove last ':' */

    return 0;
}


/*
 * step through the value [already ALIGN on 4 bytes!]
 * and call func that can convert this [and multiple
 * occurences of the value] into a human readable string.
 * usz = unity size, the fixed size of any unity in the value
 * [IF multiple unities...like ip1 ip2 ip3...]
 * buf is the destionation buffer, bs is the destination buffer
 * size.
 * dptype and dplen are the dhcp-type/len respectively
 * func is the function-pointer to a function that
 * can convert the value into a human readable string.
 */
static char *
dec_dpval(char *buf, int bs, unsigned char dptype, unsigned char dplen, unsigned char *abuf,
                 int (*func)(char *, int, char *, unsigned char), unsigned char usz)
{
    unsigned char aoff = 0;
    int slen;

    if (buf == NULL)
        return NULL;

    memset(buf, 0, bs);
    while (aoff+usz <= dplen)
    {
        if ( (slen = strlen(buf)) >= bs)
            break;  /* we need this: size_t is unsigned */
        func(buf+slen, bs-slen, abuf+aoff, usz);
        aoff += usz;
        if ((dhcpnfo[dptype].enctype & DHCP_MULTI))
            continue;
        break;
    }    

    return buf;
}


/*
 * convert dhcp-value string <type><len><value> into human
 * readable string
 * requirement from caller:
 *  value[dplen-1] is valid memory location 
 *  buf != null
 * this function is not reentrant (who needs this anyway ?)
 */
char *
dhcp_val2str(char *buf, int bsize, unsigned char dptype, unsigned char dplen, unsigned char *value)
{
#define DBSZ    1024
    unsigned char c;
    int slen, aoff;
    unsigned char abuf[255]; /* max of dplen */
    unsigned char dbuf[DBSZ];   /* max len that 'func' can generate */


    if (buf == NULL)
        return NULL;

    if (bsize <= 0)
        return NULL;

    memcpy(abuf, value, dplen);  /* alignment */
    memset(buf, 0, bsize);     
    //memset(dbuf, 0, sizeof dbuf);

    if (dptype > DHCP_MAXTAG)
    {
        snprintf(buf, bsize, "UNKNOWN dhcp type %d[%d]", dptype, dplen);
        return buf;
    }

    aoff = 0;
    snprintf(buf, bsize, "%s: ", dhcp_str(dptype));
    slen = strlen(buf);
    if (bsize <= slen)
        return NULL;
    /*
     * decode_dhcpvalue converts the value [with multiple 
     * unities, like ip1 ip2 ip3] into a human readable string.
     * Results is stored into buf+slen here
     */
    switch ( (c = dhcpnfo[dptype].enctype & DHCP_TYPEMASK) )
    {
        case DHCP_NONE:
            strcpy(dbuf, "");
            break;
        case DHCP_IPV4:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_decIPV4, 4);
            break;
        case DHCP_ASCII:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_decASCII, dplen);
            break;
        case DHCP_8I:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_dec8I, 1);
            break;
        case DHCP_8UI:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_dec8UI, 1);
            break;
        case DHCP_16I:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_dec16I, 2);
            break;
        case DHCP_16UI:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_dec16UI, 2);
            break;
        case DHCP_32I:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_dec32I, 4);
            break;
        case DHCP_32UI:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_dec32UI, 4);
            break;
        case DHCP_32TIME:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_dec32TIME, 4);
            break;
        case DHCP_1HEX:
        case DHCP_HEX:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_decHEX, dplen);
            break;
        case DHCP_MAC:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_decMAC, dplen);
            break;
        case DHCP_BOOL:
            dec_dpval(dbuf, DBSZ, dptype, dplen, abuf, dp_decBOOL, 1);
            break;
        default:
            snprintf(dbuf, DBSZ, " UNKNOWN encoding type %d", c); 
            break;
    }
    strncpy(buf+slen, dbuf, bsize - slen);
    *(buf + bsize - 1) = '\0';

    return NULL;
}

/*
 * Add default options.
 */
void
dhcp_set_default(struct _dhcpset *ds)
{
	dhcp_add_suboption(ds, DHCP_SUBMASK);
	dhcp_add_suboption(ds, DHCP_TIMEOFF);
	dhcp_add_suboption(ds, DHCP_ROUTER);
	dhcp_add_suboption(ds, DHCP_DNS);
	dhcp_add_suboption(ds, DHCP_HOSTNAME);
	dhcp_add_suboption(ds, DHCP_DOMAIN);
	dhcp_add_suboption(ds, DHCP_BCAST);
	dhcp_add_suboption(ds, DHCP_MASKDISC);
	dhcp_add_suboption(ds, DHCP_ROUTDISC);
	dhcp_add_suboption(ds, DHCP_STATROUTES);
	dhcp_add_suboption(ds, DHCP_NISDOM);
	dhcp_add_suboption(ds, DHCP_NISSERV);
	dhcp_add_suboption(ds, DHCP_NTP);
	dhcp_add_suboption(ds, DHCP_NBNS);
	dhcp_add_suboption(ds, DHCP_NBDD);
}

