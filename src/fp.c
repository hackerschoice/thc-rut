/*
 * $Id: fp.c,v 1.6 2003/05/15 12:13:49 skyper Exp $
 *
 * Port State and Banner fingerprinting.
 * NMAP tests can be found in a different file (nmap_compat.c).
 *
 * See thcrut-os-fingperprints for format informations.
 *
 * Changelog
 * - added banner matching support (libpre)
 */

#include "default.h"
#include <string.h>
#include <pcre.h>
#include "fp.h"

static char *chomp2(char *buf);
static void FP_addline(struct _fp_testsuite *fp, char *line, unsigned long class, unsigned short ofs_string, size_t n_line);
static char *FP_ITEM_next(char *item);
static int FP_TS_addtest(char **val, char *accuracy, struct _fp_testsuite *fpts, char *item);


/*
 * Convert a class string into a integer value
 * 2.2.1.2.3 = Unix, Solaris, 2.8, whatever
 *
 * see _classid definition of how it is split up.
 */
#define FP_SCREWUP(CLID, MARK, STR) do{ \
	char *ptr; \
	if (!(ptr = strchr(STR, '.'))) \
	{ \
		CLID.st.MARK = atoi(STR); \
		return CLID.id; \
	} \
	*ptr++ = '\0'; \
	CLID.st.MARK = atoi(STR); \
	STR = ptr; \
}while(0)
unsigned int
FP_class2int(const char *input)
{
	char buf[512];
	char *str = buf;
	union _classid clid;

	clid.id = 0;

	/* FIXME: strlcpy() */
	snprintf(buf, sizeof buf, "%s", input);

	FP_SCREWUP(clid, genre, str);
	FP_SCREWUP(clid, vendor, str);
	FP_SCREWUP(clid, os, str);
	FP_SCREWUP(clid, d, str);
	FP_SCREWUP(clid, dd, str);
	FP_SCREWUP(clid, ddd, str);

	return clid.id;
}

/*
 * Converts a class number (long) into
 * dotted notation. dst might be a buffer supplied by the user
 * 'long enough' to hold the data. 32byte is fine...
 * This routine is slow.
 */
char *
FP_class2str(char *dst, unsigned int val)
{
	static char mybuf[32];
	char *buf;
	union _classid clid;

	clid.id = val;

	if (dst)
		buf = dst;
	else
		buf = mybuf;

	if (clid.st.ddd)
		snprintf(buf, 32, "%d.%d.%d.%d.%d.%d", clid.st.genre, clid.st.vendor, clid.st.os, clid.st.d, clid.st.dd, clid.st.ddd);
	else if (clid.st.dd)
		snprintf(buf, 32, "%d.%d.%d.%d.%d", clid.st.genre, clid.st.vendor, clid.st.os, clid.st.d, clid.st.dd);
	else if (clid.st.d)
		snprintf(buf, 32, "%d.%d.%d.%d", clid.st.genre, clid.st.vendor, clid.st.os, clid.st.d);
	else
		snprintf(buf, 32, "%d.%d.%d", clid.st.genre, clid.st.vendor, clid.st.os);
		
	return buf;
}

/*
 * Remove spaces and comments on both sides.
 */
static char *
chomp2(char *buf)
{
	char *end, *ptr;
	char inside_quote = 0;

	/* Remove comments  from end */
#if 0
	/* Conflict if regex strings contains '#' sign */
	if ( (ptr = strchr(buf, '#')))
	{
		*ptr = '\0';
		end = ptr;
	} else
#endif
	if (*buf == '#')
		return NULL;

	while ((*buf) && ((*buf == '\t') || (*buf == ' ')))
		buf++;

	ptr = buf;

	/*
	 * Remove comment from right side
	 * e.g. find first occurance of # outside the quotes.
	 */
	while (*ptr)
	{
		/* Ignore escaped quotes in quotes "\"" etc */
		if (*ptr == '\\')
		{
			ptr++;
			goto next;
		}

		if (*ptr == '"')
			inside_quote ^= 1; /* swap */
		if (inside_quote)
			goto next;

		/* Here we are outside quotes! */
		if (*ptr == '#')
		{
			*ptr = '\0';
			break;
		}
next:
		ptr++;
	}

	end = buf + strlen(buf) - 1;

	while ((end >= buf) && ((*end == ' ') || (*end == '\t') || (*end == '\n')))
	{
		*end = '\0';
		end--;
	}

	while ( (buf < end) && ((*buf == ' ') || (*buf == '\t')))
		buf++;

	return buf;
}

/*
 * Read in FP file and create the testsuite.
 *
 * We keep a list of every test per Fingerprint and a list
 * of all unique tests to perform. For the latter one do we
 * first check if the test is already in the testsuite and add
 * it if necessary.
 *
 * We have to lookup the class by the results we got from a target.
 * Hashing does not seem to be possible.
 */
int
FP_TS_load(struct _fp_testsuite *fpts, const char *filename)
{
	FILE *fp;
	char buf[1024];
	char *ptr;
	unsigned int class = 0;
	unsigned short ofs_string = 0;
	size_t inuse = 0, size = 0, fpname_len;
	size_t n_line = 0;

	fp = fopen(filename, "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof buf, fp))
	{
		n_line++;
		ptr = chomp2(buf);
		if ((!ptr) || (*ptr == '\0'))
			continue;
		if (strncmp("Fingerprint", ptr, 11) == 0)
		{
			ptr += 11;
			if (*ptr == ':')
			{
				class = FP_class2int(ptr + 1);
				ptr = strchr(ptr + 1, ' ');
				if (!ptr)
					continue;
				ptr++;
			} else
				class = 0;
			fpname_len = strlen(ptr) + 1;  /* cp also \0 */
			if (fpname_len > size - inuse)
			{
				size = (size + fpname_len + 4096)&~0xFFF;
				fpts->strings = realloc(fpts->strings, size);
			}
			memcpy(fpts->strings + inuse, ptr, fpname_len);
			ofs_string = inuse;
			inuse += fpname_len;

			continue; /* next line */
		}
		FP_addline(fpts, ptr, class, ofs_string, n_line);
	}
	fclose(fp);

	return 0;
}

/*
 * Add test to testsuite if not already included.
 * item is a %-free test item (e.g. "135T=O").
 *
 * Return number of this test in the test suites.
 * Return -1 on error (>= 0 are valid entries).
 *
 * We trust our input here. All data comes from a file.
 *
 * <port><TEST char>[<accuracy digit>]=<value: string, open, close>
 */
static int
FP_TS_addtest(char **val, char *accuracy, struct _fp_testsuite *fpts, char *item)
{
	char *eq = strchr(item, '=');
	char type;
	unsigned short port;
	int i;
	struct _fp_ts_test *tests;
	unsigned char *n_testsp;
	unsigned char cat;
	char *ptr;
	unsigned char c;

	if (!eq)
		return -1;

	/*
	 * Extract accuracy value which follows the TEST symbol
	 * (T, U, W, B, ..)
	 */
	*eq = '\0';
	ptr = eq;
	while ((c = *--ptr))
	{
		if (((c >= '0') && (c <= '9')) || (c == '-'))
			continue;

		break;
	}

	type = *ptr;  /* Test type */
	*ptr = '\0';
	port = atoi(item);
	if (!port)
		return -1;

	/*
	 * The accuracy value
	 */
	if ((ptr + 1) < eq)
		*accuracy = atoi(ptr + 1);
	else
		*accuracy = -128;  /* NO accuracy set, use default later */

	*val = eq + 1;

	/*
	 * Parse the item
	 */
	switch (type)
	{
	case 'T':
		cat = FP_CAT_TCP;
		tests = fpts->cat[FP_CAT_TCP].tests;
		n_testsp = &fpts->cat[FP_CAT_TCP].n_tests;
		break;
	case 'U':
		cat = FP_CAT_UDP;
		tests = fpts->cat[FP_CAT_UDP].tests;
		n_testsp = &fpts->cat[FP_CAT_UDP].n_tests;
		break;
	case 'W':  /* GET / HTTP/1.0 */
		cat = FP_CAT_WWW;
		tests = fpts->cat[FP_CAT_WWW].tests;
		n_testsp = &fpts->cat[FP_CAT_WWW].n_tests;
		break;
	case 'B':
		cat = FP_CAT_BANNER;
		tests = fpts->cat[FP_CAT_BANNER].tests;
		n_testsp = &fpts->cat[FP_CAT_BANNER].n_tests;
		break;
	case 'S':
		cat = FP_CAT_SNMP;
		tests = fpts->cat[FP_CAT_SNMP].tests;
		n_testsp = &fpts->cat[FP_CAT_SNMP].n_tests;
		break;
	case 'N':
		cat = FP_CAT_NVT;
		tests = fpts->cat[FP_CAT_NVT].tests;
		n_testsp = &fpts->cat[FP_CAT_NVT].n_tests;
		break;
	default:
		fprintf(stderr, "Unknown test: \"%s%c=\"\n", item, type);
		return -1;
	}

	for (i = 0; i < *n_testsp; i++)
		if (tests[i].port == port)
			return FP_TEST_CAT_NR(cat, i);

	/* Add to testsuite */
	tests[*n_testsp].port = port;
	*n_testsp = *n_testsp + 1;
	fpts->n_tests++;

	return FP_TEST_CAT_NR(cat, i);
}

/*
 * Return next item of a line.
 * First call should be done with a pointer to the string, next call with NULL.
 *
 * Return NULL if no more items left.
 */
static char *
FP_ITEM_next(char *line)
{
	static char *myline;
	char *ptr;
	char *item;

	/* 
	 * Initialize
	 */
	if (line)
	{
		myline = line;

		while (*myline == '%')
			myline++;

		return NULL;
	}

	/*
	 * No more items left in this line.
	 */
	if (!myline)
		return NULL;

	ptr = strchr(myline, '%');
	if (ptr)
		*ptr++ = '\0';
	item = myline;
	myline = ptr;

	return item;
}

/*
 * Parse a test-line (which always follows a 'Fingerprint.*' line.
 * Every new test found is linked into the test suite.
 * The testline itself is linked into the fingerprint-database.
 */
static void
FP_addline(struct _fp_testsuite *fpts, char *line, unsigned long class, unsigned short ofs_string, size_t n_line)
{
	char *ptr = line;
	int n = 0;
	char inside_quote = 0;
	char *item;
	char *val;
	int testnr_cat;
	struct _fp *myfp = NULL;
	struct _fp_test *fpt;
	static struct _fp *lastfp;
	const char *error;
	int errptr;
	char accuracy;

	while (*ptr)
	{
		/* Ignore escaped quotes in quotes "\"" etc */
		if (*ptr == '\\')
		{
			ptr++;
			goto next;
		}

		if (*ptr == '"')
			inside_quote ^= 1; /* swap */

		if ((!inside_quote) && (*ptr == '%'))
			n++;
next:
		ptr++;
	}
	n++; /* No '%' found means 1 line => 1 test */

	myfp = calloc(1, sizeof *myfp + n * sizeof(struct _fp_test));
	myfp->n_tests = 0;
	myfp->class = class;
	myfp->ofs_string = ofs_string;

	FP_ITEM_next(line);
	while ( (item = FP_ITEM_next(NULL)))
	{

		/* get back number of this test. */
		testnr_cat = FP_TS_addtest(&val, &accuracy, fpts, item);
		if (testnr_cat < 0)
			continue;

		fpt = &myfp->fp_tests[myfp->n_tests++];
		fpt->testnr_cat = testnr_cat;

		switch (*val)
		{
		case 'U':
		case 'O':
			fpt->flags = FP_TEST_OPEN;
			if (accuracy != -128)
				fpt->accuracy = accuracy;
			else
				fpt->accuracy = 1;
			break;
		case 'C':
			fpt->flags = FP_TEST_CLOSED;
			if (accuracy != -128)
				fpt->accuracy = accuracy;
			else
				fpt->accuracy = 1;
			break;
		case '"':
			fpt->flags = FP_TEST_REGEX;
			if (accuracy != -128)
				fpt->accuracy = accuracy;
			else
				fpt->accuracy = 2;  /* 2 by default; regex */
			val++;
			ptr = val;
			while ((*ptr) && (*ptr != '"'))
			{
				/*
				 * Skip '\"' for example.
				 */
				if (*ptr == '\\')
					ptr++;
				if (*ptr)
					ptr++;
			}
			*ptr = '\0';
			fpt->pattern = pcre_compile(val, 0, &error, &errptr, NULL);
			if (!fpt->pattern)
			{
				fprintf(stderr, "string: \"%s\"\n", val);
				fprintf(stderr, "%d: parse error in regex at %d: %s\n", n_line, errptr, error);
				exit(-1);
			}
			fpt->hints = pcre_study(fpt->pattern, 0, &error);
			if (error != NULL)
			{
				fprintf(stderr, "%d: error in pcre_study: %s\n", n_line, error);
				exit(-1);
			}
			//fpt->str = strdup(val);
			break;
		default:
			fprintf(stderr, "Unknown type behind '='\n");
		}
	}

	/*
	 * New FP's are add at the tail. Should not be changed as it would
	 * change the semantic of thcrut-os-fingerprint (upward down order
	 * or downward-up).
	 */
	if (!fpts->fps)
		fpts->fps = myfp;
	else
		lastfp->next = myfp;
	lastfp = myfp;
}

/*
 * Debug function.
 *
 * Dump the Testsuite.
 */
void
FP_TS_dump(struct _fp_testsuite *fpts)
{
	int n, cat;
	struct _fp *fp = fpts->fps;


	while (fp)
	{
		fprintf(stderr, "%s (%u) with %d tests\n", fpts->strings + fp->ofs_string, fp->class, fp->n_tests);
		fp = fp->next;
	}

	fprintf(stderr, "Total number of tests: %d\n", fpts->n_tests);
	for (cat = 0; cat < sizeof fpts->cat / sizeof *fpts->cat; cat++)
	{
		for (n = 0; n < fpts->cat[cat].n_tests; n++)
			printf("%d\n", fpts->cat[cat].tests[n].port);
	}
}

