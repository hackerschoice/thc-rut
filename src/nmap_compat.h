/*
 * $Id: nmap_compat.h,v 1.1 2002/12/07 20:45:43 skyper Exp $
 *
 * Make THCrut process nmap-of-fingerprint files.
 * We use a slightly more performant algorithm to load the strings
 * into memory.
 */

#ifndef __THCRUT_NMAP_COMPAT_H__
#define __THCRUT_NMAP_COMPAT_H__ 1

#include <sys/types.h>

#define NMAP_HASH_SIZE    (113)
#define NMAP_DF_ISNOTSET(item)  ((item)->df & 0x1)
#define NMAP_DF_ISSET(item)  ((item)->df & 0x2)

#define NMAP_DF_SET_ISNOTSET(item)  ((item)->df |= 0x1)
#define NMAP_DF_SET_ISSET(item)  ((item)->df |= 0x2)

#define NMAP_FP_TONE "\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000" 
#define NMAP_FP_TONE_LEN 20

/*
 * All in HBO
 */
struct _nmap_osfp_TONE
{
	struct _nmap_osfp_TONE *next;
	unsigned long ops:30; /* 10 ops */
	unsigned long df:2;
	unsigned short wsize; /* windows size */
	unsigned long ofs_string;
	unsigned long class;
};

/*
 * HASH shall be the (wsize ^ var) % HASH_SIZE
 */
struct _nmap_osfp
{
	char *strings;
	struct _nmap_osfp_TONE *hash_tone[NMAP_HASH_SIZE];
};

/*
 * This is the evil shit.
 * We check a test-1-entry from the DB if the value match against
 * it.
 *
 * Decoded is it:
 * if (tone->wsize != wsize)
 * 	continue;
 * if (tone->ops != ops)
 *	continue;
 * if ((df) && (NMAP_DF_ISSET(tone)))
 * 	return tone;
 * if ((!df) && NMAP_DF_ISNOTSET(tone))
 * 	return tone;
 */
#define NMAP_TONE_MATCH(tone, mywsize, mydf, myops)  ((tone)->wsize != mywsize?0: (tone)->ops != myops?0:(mydf) && NMAP_DF_ISSET(tone)?1:(!mydf) && NMAP_DF_ISNOTSET(tone)?1:0)

long NMAP_class2long(const char *input);
int NMAP_load_fp(struct _nmap_osfp *osfp, char *file);
struct _nmap_osfp_TONE *NMAP_lookup(struct _nmap_osfp *osfp, unsigned short wsize, char df, unsigned long ops);
unsigned long NMAP_tcpops2ops(char *opstr, unsigned char *buf, size_t len);
char * NMAP_long2class(char *dst, long val);

#endif /* !__THCRUT_NMAP_COMPAT_H__ */

