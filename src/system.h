/*
 * $Id: system.h,v 1.1 2003/05/15 12:13:49 skyper Exp $
 */


#ifndef __THCRUT_SYSTEM_H__
#define __THCRUT_SYSTEM_H__ 1

#include <sys/types.h>

void hexdump(unsigned char *data, size_t len);
int perlstring(char *dst, int dlen, char *src, int slen);
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif
char *int2bit(unsigned int val);

#endif /* !__THCRUT_SYSTEM_H__ */

