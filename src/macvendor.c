#include "default.h"
#include <ctype.h>
#include "macvendor.h"

/*
 * this is experimental code. we dont HASH atm.
 * FIXME
 */
#define HASH_vtag(t1, t2, t3) ((t1+t2+t3)% VTAG_MAX_HASH)
#define TAG2MYTAG(t) ((t[0]<<8) + (t[1]<<4) + t[2]) 

struct _i_vendorset
{
	unsigned long mytag;
	char *vendor;
};

static struct _i_vendorset *i_vendorsetptr = NULL;

static char *
buf2macvendor(char *buf, unsigned char *tag)
{
    unsigned short int i1=0,i2=0,i3=0;
    char *ptr, *ptr2;

    if (!isxdigit((int)buf[0]))
        return NULL; /* skip everything that does not look like a mac */

    if (sscanf(buf, "%hx:%hx:%hx", &i1, &i2, &i3) != 3)
        return NULL;
    tag[0] = (unsigned char)i1;
    tag[1] = (unsigned char)i2;
    tag[2] = (unsigned char)i3;

    if ( (ptr = strchr(buf, '\t')) == NULL)
        if ( (ptr = strchr(buf, ' ')) == NULL)
            return NULL;   /* no \t seperatioin ?! bad...*/

    while ( (*ptr != '\0') && ( (*ptr == '\t') || (*ptr == ' ') ) )
        ptr++;

    if ( (ptr2 = strchr(ptr, '\n')) != NULL)
        *ptr2 = '\0';   /* remove the \n from fgets */

    return ptr;
}


/*
 * read in
 * return 0 on success
 * -2, macs/vendor file not found
 * -1 unknown error
 * -3 not enough memory
 * -4 fseek failed
 *
 * We first step through the file and read the vendornamed.
 * We realloc enough memory to hold all the strings in _one_ line.
 * This saves a lot of memory (coz we dont waste 12 extra bytes for
 * every malloced region the libc needs).
 * Next we step through the file again and place all the pointers
 * to our vendor-strings into memories + the tag's (converted to long int's)
 * (we cant do this in one while loop coz there is no guarantee that
 * realloc just enlarges the pointer instead of moving the already allocated
 * memory to another memory range).
 *
 * We need 80% less memory compared to the amount we need when
 * we use linked-list with allocated memory for each i
 * vendor-name + tag-name.
 * And yes..we can do this here..coz its a fixed "list" of vendors.
 * It never changes during execution.
 * Let's implement hash-table for faster lookup sometimes later....
 *
 * FIXME: Use binary tree for lookup. Mac's are sorted in manuf anyway!.
 * FIXME: heheh. this routine is old. Should replace it with a nice one.
 */
int
readvendornames(char *file)
{
	FILE *fptr = NULL;
	char buf[256];
	char *ptr, *ptr2;
	unsigned char tag[3];
	unsigned long vendorlen = 0;
	unsigned long vendorptrlen = 0;
	unsigned long vendornum = 0;
	char *vendorptr = NULL;

	fptr = fopen(file, "r");
	if (!fptr)
		return -2;

	/* FIXME: bah. get rid of realloc! */
	vendornum = 0;
	while ( fgets(buf, sizeof(buf), fptr) != NULL)
	{
		if ( (ptr = buf2macvendor(buf, tag)) == NULL)
			continue;

		if ((vendorptrlen - vendorlen) < strlen(ptr)+1)
		{
			if ( (vendorptr = realloc(vendorptr, vendorptrlen + 4096)) == NULL)
				return -3;
			vendorptrlen += 4096;
		}

		ptr2 = ptr;
		do
		{
			if (*ptr2 == '\t')
				*ptr2 = ' ';
		} while (*ptr2++ != '\0');
		memcpy(vendorptr + vendorlen, ptr, strlen(ptr)+1);
		vendorlen += strlen(ptr)+1;
		vendornum++;
	} /* eo only first round to get vendorptr fixed and loaded */

	if (fseek(fptr, 0L, SEEK_SET) != 0)
		return -4;

	/* one extra for NULL NULL EO set */
	i_vendorsetptr = malloc(sizeof(*i_vendorsetptr) * (vendornum + 1));
	vendornum = 0;
	vendorlen = 0;
	while ( fgets(buf, sizeof(buf), fptr) != NULL)
	{
		if ( (ptr = buf2macvendor(buf, tag)) == NULL)
			continue;

		(i_vendorsetptr+vendornum)->mytag = TAG2MYTAG(tag);
		(i_vendorsetptr+vendornum)->vendor = (char *)(vendorptr + vendorlen);

		vendorlen += strlen(ptr)+1;
		vendornum++;
	}

	(i_vendorsetptr+vendornum)->mytag = 0;
	(i_vendorsetptr+vendornum)->vendor = NULL;
    
	fclose(fptr);

	return 0;
}

/*
 * return name of vendor from mac/tag of with a max of len chars
 * including the terminating \0
 * len = 0 => unlimited original length found in the file.
 * we return NULL if tag not found (is this good ? "" or "<unknown>" 
 * is also kewl....hmm)
 *
 * return in rbuf (if != NULL) or our own internal static
 * variable IF rbuf == NULL!
 * OLD: mac2vendor(char *rbuf, unsigned char *tag, unsigned int len)
 */
char *
mac2vendor(unsigned char *tag)
{
    struct _i_vendorset *vsptr = i_vendorsetptr;
    struct _i_vendorset vs;
//    static char buf[128];
#if 0
    char *ptr = rbuf;
#endif

	if (tag == NULL)    /* craqhead ! N0 T4G == N0 RESULTZ */
		return NULL;
	if (vsptr == NULL)
		return NULL;

#if 0
    if ((rbuf == NULL) && (len > sizeof(buf)-1))
        len = sizeof(buf)-1;
    if (rbuf == NULL)
        ptr = buf;
#endif

	vs.mytag = TAG2MYTAG(tag);  /* mytag could be opague */

	while ( (vsptr->vendor != NULL))
	{
		if (vs.mytag == vsptr->mytag)
			break;
		vsptr++; 
	}

 	return vsptr->vendor;

#if 0
    if (vsptr->vendor == NULL)
        return NULL;

    strncpy(ptr, vsptr->vendor, len);
    *(ptr+len-1) = '\0';

    return ptr;
#endif
}

