/*
 * Vendor <-> mac 
 * RUT, anonymous@segfault.net
 */

#ifndef THCRUT_MACVENDOR_H
#define THCRUT_MACVENDOR_H 1

#define VTAG_MAX_HASH   255


struct _macvendor
{
	unsigned char  tag[3];
	char    *vendor;
};

char *mac2vendor(unsigned char *tag);

#endif /* !THCRUT_MACVENDOR_H */

