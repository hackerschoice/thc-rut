/*
 * $Id: system.c,v 1.1 2003/05/15 12:13:49 skyper Exp $
 */

#include "default.h"
#include <stdio.h>
#include <string.h>

static unsigned char esctable[] = "\x80\x80\x80\x80\x80\x80\x80\x80\x80\xF4\xEE\x80\x80\xF2\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80 \xA1\xA2#\xA4%&'\xA8\xA9\xAA\xAB,-\xAE/0123456789:;<=>\xBF@ABCDEFGHIJKLMNOPQRSTUVWXYZ\xDB\xDC]\xDE_`abcdefghijklmnopqrstuvwxyz\xFB\xFC}~\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80";


/*
 * Convert a (binary) string into a perl style string.
 *
 * Input:
 *    src and slen are the source and length to be translated.
 *     
 *  Output:
 *    dst and dlen are destionation and max. destination length.
 *
 *  Return:
 *    Number of chars placed into dst. dst will be \0 terminated.
 *
 *  Warning:
 *    This is not exactly a perl like string. We also escape " here.
 */
int
perlstring(char *dst, int dlen, char *src, int slen)
{
	unsigned char s;
	char *start = dst;
	char *end = dst + dlen;

	while ((slen-- > 0) && (dst + 4 < end))
	{
		s = *src++;
		if (esctable[s] == 0x80)
		{
			snprintf(dst, dlen, "\\x%2.2x", s);
			dst += 4;
			continue;
		}

		/*
		 * Escape the following chars:
		 * \ | ( ) [ { ^ $ * + ? . "
		 *
		 * Where " is the non-perl critical character.
		 */
		if (esctable[s] > 0x80)
		{
			*dst++ = '\\';
			*dst++ = esctable[s] - 0x80;
			continue;
		}

		*dst++ = s;
	}

	*dst = '\0';

	return dst - start;
}

void
hexdump(uint8_t *data, size_t len)
{
        size_t n = 0;
	int line = 0;

	if (!len)
		return;

	fprintf(stderr, "%03x: ", line++);
	while (1)
	{
		fprintf(stderr, "%2.2x ", data[n++]);
		if (n >= len)
			break;
		if (n % 8 == 0)
			fprintf(stderr, " - "); 
		if (n % 16 == 0)
			fprintf(stderr, "\n%03x: ", line++);
	}
	fprintf(stderr, "\n");
}

#ifndef HAVE_STRLCPY
/*           
 * bsd'sh strlcpy().
 * The strlcpy() function copies up to size-1 characters from the
 * NUL-terminated string src to dst, NUL-terminating the result.
 * Return: total length of the string tried to create.
 */
size_t
strlcpy(char *dst, const char *src, size_t size)
{
        size_t len = strlen(src);
        size_t ret = len;

        if (size <= 0)
		return 0;
	if (len >= size)
		len = size - 1;
	memcpy(dst, src, len);
	dst[len] = 0;

	return ret;
}
#endif

/*
 * Debuggging...
 * Convert an interger to a bit string and output it.
 * Most significatn bit first.
 */
char *
int2bit(unsigned int val)
{
	static char buf[33 + 3];
	char *ptr = buf;
	unsigned int i = 0x1 << 31;
	int round = 0;

	while (i > 0)
	{

		if (val & i)
			*ptr++ = '1';
		else
			*ptr++ = '0';

		i = i >> 1;

		if ((++round % 8 == 0) && (i > 0))
			*ptr++ = '.';
	}

	*ptr = '\0';

	return buf;
}

