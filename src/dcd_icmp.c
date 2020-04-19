/*
 *
 * based on information from
 *   RFC792 - INTERNET CONTROL MESSAGE PROTOCOL
 *   RFC950 - Internet Standard Subnetting Procedure
 *   ??? "ICMP Usage in Scanning" (ICMP_Scanning_v2.5.pdf)
 */

#include <stdio.h>
#include "dcd_icmp.h"

static char *	icmp_echo_reply[] = {
	"ICMP ECHOREPLY",
	NULL
};

static char *	icmp_unreach[] = {
	"ICMP UNREACH network unreachable",
	"ICMP UNREACH host unreachable",
	"ICMP UNREACH protocol unreachable",
	"ICMP UNREACH port unreachable",
	"ICMP UNREACH fragmentation needed but don't-fragment bit set",
	"ICMP UNREACH source route failed",
	"ICMP UNREACH destination network unknown",
	"ICMP UNREACH destination host unknown",
	"ICMP UNREACH source host isolated",
	"ICMP UNREACH destination network administratively prohibited",
	"ICMP UNREACH destination host administratively prohibited",
	"ICMP UNREACH network unreachable for TOS",
	"ICMP UNREACH host unreachable for TOS",
	"ICMP UNREACH communication administratively prohibited by filtering",
	"ICMP UNREACH host precedence violation",
	"ICMP UNREACH precedence cutoff in effect",
	NULL
};

static char *	icmp_quench[] = {
	"ICMP QUENCH",
	NULL
};

static char *	icmp_redirect[] = {
	"ICMP REDIRECT Redirect datagrams for the Network",
	"ICMP REDIRECT Redirect datagrams for the Host",
	"ICMP REDIRECT Redirect datagrams for the Type of Service and Network",
	"ICMP REDIRECT Redirect datagrams for the Type of Service and Host",
	NULL
};

static char *	icmp_alternate[] = {
	"ICMP ALTERNATEHOSTADDRESS",
	NULL
};

static char *	icmp_echo[] = {
	"ICMP ECHO",
	NULL
};

static char *	icmp_routerad[] = {
	"ICMP ROUTERADVERTISEMENT",
	NULL
};

static char *	icmp_routersel[] = {
	"ICMP ROUTERSELECTION",
	NULL
};

static char *	icmp_timeexceed[] = {
	"ICMP TIMEEXCEED time to live exceeded in transit",
	"ICMP TIMEEXCEED fragment reassembly time exceeded",
	NULL
};

static char *	icmp_parprob[] = {
	"ICMP PARAMETER pointer indicates the error",
	"ICMP PARAMETER missing a required option",
	"ICMP PARAMETER bad length",
	NULL
};

static char *	icmp_timestamp[] = {
	"ICMP TIMESTAMP",
	NULL
};

static char *	icmp_timestamp_reply[] = {
	"ICMP TIMESTAMPREPLY",
	NULL
};

static char *	icmp_information[] = {
	"ICMP INFORMATION",
	NULL
};

static char *	icmp_information_reply[] = {
	"ICMP INFORMATIONREPLY",
	NULL
};

static char *	icmp_addressmask[] = {
	"ICMP ADDRESSMASK",
	NULL
};

static char *	icmp_addressmask_reply[] = {
	"ICMP ADDRESSMASKREPLY",
	NULL
};

static char *	icmp_ERR[] = {
	"ICMP invalid code",
	NULL
};

struct icmp_typeelem {
	int		count;
	char **		tab;
};

struct icmp_typeelem 	icmp_tab[] = {
	{  1, icmp_echo_reply },	/*  0  Echo Reply */
	{  0, icmp_ERR },		/*  1  UNUSED */
	{  0, icmp_ERR },		/*  2  UNUSED */
	{ 16, icmp_unreach },		/*  3  Destination Unreachable */
	{  1, icmp_quench },		/*  4  Source Quench */
	{  4, icmp_redirect },		/*  5  Redirect */
	{  1, icmp_alternate },		/*  6  Alternate Host Address */
	{  0, icmp_ERR },		/*  7  UNUSED */
	{  1, icmp_echo },		/*  8  Echo */
	{  1, icmp_routerad },		/*  9  Router Advertisement */
	{  1, icmp_routersel },		/* 10  Router Selection */
	{  2, icmp_timeexceed },	/* 11  Time Exceeded */
	{  3, icmp_parprob },		/* 12  Parameter Problem */
	{  1, icmp_timestamp },		/* 13  Timestamp */
	{  1, icmp_timestamp_reply },	/* 14  Timestamp Reply */
	{  1, icmp_information },	/* 15  Information Request */
	{  1, icmp_information_reply },	/* 16  Information Request */
	{  1, icmp_addressmask },	/* 17  RFC950: Address Mask Request */
	{  1, icmp_addressmask_reply },	/* 18  RFC950: Address Mask Reply */
	{  0, NULL },	/* EOList */ 
};

int	icmp_type_max = (sizeof (icmp_tab) / sizeof (struct icmp_typeelem)) - 1;

const char *
icmp_str (int type, int code)
{
	struct icmp_typeelem *	it;

	if (type < 0 || type >= icmp_type_max)
		return ("ICMP invalid type");

	it = &icmp_tab[type];
	if (it->count == 0)
		return (it->tab[0]);

	if (code < 0 || code >= it->count)
		return ("ICMP invalid code");

	return (it->tab[code]);
}


