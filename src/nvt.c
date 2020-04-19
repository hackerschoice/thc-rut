/*
 * $Id: nvt.c,v 1.1 2003/05/15 12:13:49 skyper Exp $
 */

#include "nvt.h"
#include <string.h>

#define IACFOUND        0x01
#define DOFOUND         0x02
#define UNKNOWNOPT      0x04
#define SUBNEGO         0x08
#define CRFOUND         0x10
#define WILLFOUND	0x20

/*
 * RFC854 - Network Virtual Terminal
 *
 * In summary, WILL XXX is sent, by either party, to indicate that
 * party's desire (offer) to begin performing option XXX, DO XXX and
 * DON'T XXX being its positive and negative acknowledgments; similarly,
 * DO XXX is sent to indicate a desire (request) that the other party
 * (i.e., the recipient of the DO) begin performing option XXX, WILL XXX
 * and WON'T XXX being the positive and negative acknowledgments.  Since
 * the NVT is what is left when no options are enabled, the DON'T and
 * WON'T responses are guaranteed to leave the connection in a state
 * which both ends can handle.  Thus, all hosts may implement their
 * TELNET processes to be totally unaware of options that are not
 * supported, simply returning a rejection to (i.e., refusing) any
 * option request that cannot be understood.
 *
 * Or:
 * WILL -> DO
 * DO   -> WONT (except for DO TERMINAL TYPE).
 *
 * Input:
 *   data of raw NVT data of lenght len.
 *   ans should be at least 1024 chars long.
 *
 * Output:
 *   ans is the proposed answer to the NVT request of lenght alen.
 *   rem is the remaining data of length rlen.
 *
 * Requirement
 *   ans and rem must be at least len bytes in size.
 *
 * FIXME: This routine started out as a simple while() loop but
 * was debugged into existance to handle all the unknown and buggy
 * devices out there (like that Terminal Type is required).
 * It requires some rework and a real FSM.
 *
 * return 0 on success.
 */
int
NVT_decode(char *data, int len, char *ans, int *alen, char *rem, int *rlen)
{
	char *ptr = data;
	char flags = 0;
	unsigned char c;

	*rlen = 0;
	*alen = 0;

	while (1)
	{
		if ((len-- <= 0) || (*alen > 1000))
			break;
		c = *ptr++;

		if (flags & UNKNOWNOPT)
		{
			flags = 0;
			continue;
		}

		if (flags & IACFOUND)
		{
			if (c == NVT_IAC)  /* IAC IAC */
			{
				*rem++ = NVT_IAC;
				if (!(flags & SUBNEGO))
					flags = 0;
				continue;
			}

			if (flags & SUBNEGO)
			{
				if (c == NVT_SE)
					flags = 0;
				continue;
			}

			if (flags & DOFOUND)
			{
				*ans++ = NVT_IAC;
				if (c == 0x18)
					*ans++ = NVT_WILL;
				else
					*ans++ = NVT_WONT;  /* me is dump */
				*ans++ = c;
				*alen = *alen + 3;
				flags = 0;
				continue;
			}

			if (flags & WILLFOUND)
			{
				*ans++ = NVT_IAC;
				*ans++ = NVT_DO;
				*ans++ = c;
				*alen = *alen + 3;
				flags = 0;
				continue;
			}

			if (c == NVT_SB) /* sub-negotiation */	
			{
				flags = SUBNEGO;
				/*
				 * Some crappy terminal's terminate
				 * the connection if we dont send our
				 * Terminal type.
				 */
				if ((len > 1) && (*ptr == 0x18) && (*(ptr + 1) == 0x01))
				{
					memcpy(ans, "\xff\xfa\x18\x00\x56\x54\x31\x30\x30\xff\xf0", 11);
					ans += 11;
					*alen = *alen + 11;
				}

				continue;
			}

			if (c == NVT_DO)
			{
				flags |= DOFOUND;
				continue;
			} else if (c == NVT_WILL) {
				flags |= WILLFOUND;
				continue;
			} else {
				flags = ~(IACFOUND | DOFOUND);
				flags |= UNKNOWNOPT; /* skip next */
				continue;
			}

		} /* IACFOUND */

		if (flags & SUBNEGO)
			continue;

		if (c == NVT_IAC)
		{
			flags = IACFOUND;   /* first IAC */
			continue;
		}

		if (flags & CRFOUND)
		{
			if (c == '\0')
			{
				flags &= ~CRFOUND;
				*rem++ = '\r';
				*rlen = *rlen + 1;
				continue;
			}
			if (c == '\n')
			{
				flags &= ~CRFOUND;
				*rem++ = '\n';
				*rlen = *rlen + 1;
				continue;
			}
		}

		if (c == '\r')
		{
			flags |= CRFOUND;
			continue;
		}

		*rem++ = c;
		*rlen = *rlen + 1;
	}

	return 0;
}


