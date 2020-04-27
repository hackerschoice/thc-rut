/*
 * $Id: nmap_compat.c,v 1.3 2003/05/15 12:13:49 skyper Exp $
 *
 * THCrut (c)2001 The Hackers Choice
 */

#include "default.h"
#include "thc-rut.h"
#include "nmap_compat.h"
#include "fp.h"

static int wsize_tok(unsigned short *val, char *wsize);
static int add_tones(struct _nmap_osfp *osfp, char *buf, unsigned long ofs_string, unsigned long class);
static int ops_tok(unsigned long *val, char *ops);
static void NMAP_HASH_add(struct _nmap_osfp *osfp, struct _nmap_osfp_TONE *tone);


/*
 * Convert vanille tcp-options to NMAP OSFP representation.
 * return -1 on error.
 *
 * A human (nmap format) readable string of the ops is returned
 * in opstr (if supplied).
 */
unsigned long
NMAP_tcpops2ops(char *opstr, char *buf, size_t len)
{
	unsigned long ops = 0;
	int ofs = 0;
	unsigned short s;

	while (ofs < len)
	{
		ops <<= 3;
		switch (buf[ofs])
		{
		case 0: /* E, End of list */
			ops |= 6;
			ofs++;
			if (opstr)
				*opstr++ = 'E';
			break;
		case 1: /* N, NOP */
			ops |= 2;
			ofs++;
			if (opstr)
				*opstr++ = 'N';
			break;
		case 2: /* M, Max Segment Size */
			ops |= 1;
			ofs++;
			if (opstr)
				*opstr++ = 'M';
			if (ofs + 2 > len)
				break;
			s = (buf[ofs] << 8) + buf[ofs + 1];
			ofs += 3;
			if (s != 265)
				break;
			/* E, ??? */
			if (opstr)
				*opstr++ = 'E';
			ops <<= 3;
			ops |= 5;
			break;
		case 3: /* W, ??? */
			ops |= 3;
			ofs += 3;
			if (opstr)
				*opstr++ = 'W';
			break;
		case 8: /* T, ??? */
			ops |= 4;
			ofs += 10;
			if (opstr)
				*opstr++ = 'T';
			break;
		default:
			fprintf(stderr, "Unknown tcp option %x\n", buf[ofs]);
			ofs++;
		}
	}

	*opstr = '\0';

	return ops;
}

#define NMAP_TONE_ADJ        (10)

/*
 * Load nmap style fingerprint file and extract Testsuite 1 (TONE).
 * Return 0 on success.
 */
int
NMAP_load_fp(struct _nmap_osfp *osfp, char *file)
{
	FILE *fp;
	char buf[1024];
	char *ptr;
	unsigned int class = 0;
	char *end;
	size_t size = 0, inuse = 0;
	size_t fpname_len = 1;

	if (!file)
		file = getenv("NMAP_OS_FINGERPRINTS");
	if (!file)
		file = "./nmap-os-fingerprints";

	fp = fopen(file, "r");
	if (!fp)
		return -1;

	memset(osfp, 0, sizeof *osfp);

	while (fgets(buf, sizeof buf, fp))
	{
		if (*buf == '#')
			continue;
		/* Remove comment and everything after comment */
		/* FIXME: also remove all white spaces from the right. */
		/* Fucking nmap format. Cant Fyodor use a better one? */
		end = strchr(buf, '#');
		if (end)
			*end = '\0';
		else
			end = buf + strlen(buf);

		if ((*buf != 0) && (*(end - 1) == '\n'))
			*--end = '\0';

		if (end > buf)
		{
			while ((end > buf) && ((*(end - 1) == ' ') || (*(end - 1) == '\t')))
				end--;
			*end = '\0';
		}

		if (strncmp(buf, "Fingerprint", 11) == 0)
		{
			ptr = &buf[11];
			if (*ptr == ':')
			{
				if ((ptr = strchr(&buf[12], ' ')))
					*ptr++ = '\0';
				class = FP_class2int(&buf[12]);
				//fprintf(stderr, "hoaa %d\n", class);
			} else {
				ptr++;
				class = 0;
			}
//			fprintf(stderr, "OS:%d:%s\n", class, ptr);
			/* FIXME: skip without strings */
			fpname_len = end - ptr + 1;
			if (fpname_len > size - inuse)
			{
				size = (size + fpname_len + 4096)&~0xFFF;
				osfp->strings = realloc(osfp->strings, size);
			}
			memcpy(osfp->strings + inuse, ptr, fpname_len);

			continue;
		}

		if (strncmp(buf, "T1(", 3) == 0)
		{
			if (add_tones(osfp, buf, inuse, class) != 0)
				continue;
			inuse += fpname_len;
			fpname_len = 0;
		}
	}
			
	fclose(fp);

	return 0;
}

/*
 * BAH, Fyodor use a VERY STUPID format. I bet he didnt use his brain
 * how to parse this before doing the format...
 */
/*
 * Parse a T1 test line from nmap-os-fingerprints
 * Example:
 * T1(DF=N%W=0|800%ACK=S++%Flags=AR|AS%Ops=|M)
 * FIXME: We currently ignore FLAGS (can be BAS, AS, AR, ARS, APS, BAR, ..)
 * NMAP documentation is wrong when it says that T1 is performed against
 * an open port. A reply with Flags=AR is not Open for me. This has
 * been realized after implementing. Our version of the T1 test is just
 * run against an open port.
 *
 * buf is \0 terminated, might be \n terminated.
 *
 * Return 0 on success.
 *
 * We will never ever unload them.
 */
static int
add_tones(struct _nmap_osfp *osfp, char *buf, unsigned long ofs_string, unsigned long class)
{
	static long current_tone;
	static struct _nmap_osfp_TONE *tone;
	struct _nmap_osfp_TONE this;
	static long free_tone;
	char *next;
	char *df;
	char *wsize;
	char *ops;
	char *end;
	char *ptr;
	unsigned long l;

	memset(&this, 0, sizeof this);


	/* Get a good format here */
	if ( (next = strchr(buf, '(')))
		*next = '%';
	if ( (next = strchr(buf, ')')))
		*next = '%';

	/* Split it for what we check for */
	if ( (df = strstr(buf, "%DF=")))
		df += 4;
	if ( (wsize = strstr(buf, "%W=")))
		wsize += 3;
	if ( (ops = strstr(buf, "%Ops=")))
		ops += 5;
	ptr = buf;
	end = buf + strlen(buf);

	/* subst all % with 0. */
	while (ptr < end)
	{
		if (*ptr == '%')
			*ptr = '\0';
		ptr++;
	}

	if (df)
	{
		if (strchr(df, 'N'))
			NMAP_DF_SET_ISNOTSET(&this);
		if (strchr(df, 'Y'))
			NMAP_DF_SET_ISSET(&this);
	}

	wsize_tok(NULL, wsize);
	while (wsize_tok(&this.wsize, NULL) == 0)
	{
		ops_tok(NULL, ops);

		while (ops_tok(&l, NULL) == 0)
		{
			this.ops = l;
			/* Parse through the Ops... */
//			fprintf(stderr, "wsize: %ld, ops: %d, df: %d\n", this.wsize, this.ops, this.df);
			/* 
			 * Allocate in blocks.
			 */
			if (current_tone >= free_tone)
			{
				tone = calloc(NMAP_TONE_ADJ, sizeof *tone);
				current_tone = 0;
				free_tone = NMAP_TONE_ADJ;
			}

			tone->ops = this.ops;
			tone->df = this.df;
			tone->wsize = this.wsize;
			tone->ofs_string = ofs_string;
			tone->class = class;
			NMAP_HASH_add(osfp, tone);

			tone++;
			current_tone++;
		}
	}


	return 0;
}

struct _nmap_osfp_TONE *
NMAP_lookup(struct _nmap_osfp *osfp, unsigned short wsize, char df, unsigned long ops)
{
	int idx = (wsize ^ ops) % NMAP_HASH_SIZE;
	struct _nmap_osfp_TONE *tone = osfp->hash_tone[idx];

	if (!tone)
		return NULL;

	do {
//		fprintf(stderr, "%x found %s\n", tone->wsize, osfp->strings + toone->ofs_string);
		if (NMAP_TONE_MATCH(tone, wsize, df, ops))
			return tone;
#if 0
		if (tone->wsize != wsize)
			continue;
		if (tone->ops != ops)
			continue;
		if ((df) && (NMAP_DF_ISSET(tone)))
			return tone;
		if (NMAP_DF_ISNOTSET(tone))
			return tone;
#endif
	} while ( (tone = tone->next));

	return NULL;
}

static void
NMAP_HASH_add(struct _nmap_osfp *osfp, struct _nmap_osfp_TONE *tone)
{
	int idx = (tone->wsize ^ tone->ops) % NMAP_HASH_SIZE;
#if 0
	struct _nmap_osfp_TONE *old;

	old = NMAP_lookup(osfp, tone->wsize, NMAP_DF_ISSET(tone)?1:0, tone->ops);
	if (old)
		return;
//		fprintf(stderr, "FP for %s already exist: %s\n", osfp->strings + tone->ofs_string, osfp->strings + old->ofs_string);
#endif

	tone->next = osfp->hash_tone[idx];
	osfp->hash_tone[idx] = tone;
}

static int
ops_tok(unsigned long *val, char *ops)
{
	static char buf[128];
	static char *ptr;
	char *next;
	int shift;

	if (ops)
	{
		strncpy(buf, ops, sizeof buf);
		buf[sizeof buf - 1] = '\0';
		ptr = buf;

		return 0;
	}

	if (!ptr)
		return -1;

	next = strchr(ptr, '|');
	if (next)
		*next++ = '\0';

	/*
	 * max of 10 options
	 */
	*val = 0;
	shift = strlen(ptr) - 1;
	if (shift > 10)
		shift = 10;

	while (*ptr != '\0')
	{
		switch (*ptr)
		{
		case 'M':
			*val |= (1 << shift * 3);
			break;
		case 'N':
			*val |= (2 << shift * 3);
			break;
		case 'W':
			*val |= (3 << shift * 3);
			break;
		case 'T':
			*val |= (4 << shift * 3);
			break;
		case 'E':
			*val |= (5 << shift * 3);
			break;
		case 'L':
			*val |= (6 << shift * 3);
			break;
		default:
			fprintf(stderr, "Unknown OPS \"%s\"\n", ptr);
		}
		ptr++;
		shift--;
		if (shift < 0)
			break;
	}
	ptr = next;

	return 0;
}

static int
wsize_tok(unsigned short *val, char *wsize)
{
	static char *ptr;
	char *next;

	if (wsize)
	{
		ptr = wsize;
		return 0;
	}

	if (!ptr)
		return -1;

	next = strchr(ptr, '|');
	if (next)
		*next++ = '\0';

	*val = strtol(ptr, NULL, 16) & 0xffff;
	ptr = next;

	return 0;
}

