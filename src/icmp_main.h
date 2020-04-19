/*
 * $Id:$
 */

#ifndef __THCRUT_ICMP_MAIN_H__
#define __THCRUT_ICMP_MAIN_H__ 1

#include "state.h"

struct _state_icmp
{
	struct _state state;
	char flags;
};
#define FL_ST_ECHO      0x01
#define FL_ST_AMASK     0x02
#define FL_ST_RSOL      0x04

int icmp_main(int argc, char *argv[]);

#endif /* !__THCRUT_ICMP_MAIN_H__ */
