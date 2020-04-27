/*
 * $Id: fp.h,v 1.6 2003/05/16 08:58:45 skyper Exp $
 *
 * Port State fingerprinting
 */

#ifndef __THCRUT_FP_H__
#define __THCRUT_FP_H__ 1
#include <pcre.h>
#include <libnet.h>

/*
 * We store category<->testnr value in one tuple.
 *
 * The introduction of categories was probably a design mistake.
 * The idea was to have the tests sorted by category so that
 * tests from one category can be performed before another category.
 * It makes for example sense to run the banner-grapping tests
 * before the open ports tests.
 *
 * We enumarate each tests so that we can look them up quickly when
 * we have to make a decission if a test matches the results of a host.
 * This would be easier with a linear number of tests and would
 * not require a switchtable.
 *
 * To still have them sorted by category but linear numbered we should
 * sort them after we read them in and do the enumeration after
 * sorting (e.g. a for loop through all categories that copies the
 * tests one by one). This would require to read in the file
 * twice. First to load and sort the Testsuite itself, then to
 * assign the testnumber to the single test-lines.
 */ 
#define FP_TEST_CAT_NR(cat, nr)   (((nr & 0x1f) << 3) | (cat & 0x7))
#define FP_TEST_NR(test)    (((test)->testnr_cat & ~0x7) >> 3)
#define FP_TEST_CAT(test)   ((test)->testnr_cat & 0x7)
struct _fp_test
{
	pcre *pattern;
	pcre_extra *hints;
	unsigned char testnr_cat; /* Number and cat of this test */
	unsigned char flags;      /* port state */
	char *varname;            /* != NULL: It's a variable. use accuracy */
	                          /* value from variable-hash.              */
	char accuracy;            /* 1 for port, 2 for banner default */
};

#define FP_TEST_CLOSED   0x01 /* same for UDP/TCP */
#define FP_TEST_OPEN     0x02
#define FP_TEST_REGEX    0x03 /* Must match string *str */

/*
 * One 'Fingerprint.*' line may be followed by many
 * fingerprint test lines. Currently we allocate a new _fp for each
 * of these lines even if they all point to the same Fingerprint.* line.
 */
struct _fp
{
	struct _fp *next;
	unsigned int class;
	unsigned short ofs_string;

	unsigned char n_tests;       /* Number of checks for THIS fp */
	struct _fp_test fp_tests[0]; /* we love C */
};


/*
 * Type W is the www test.
 * W test occupies 4 bytes of memory
 * S test occupies 4 bytes of memory
 * T and U test 2 bytes
 *
 * We can even use static char here. We dont expect the user
 * to have more than 128 different ports.
 * 
 * Testsuite must carry the human representation of the tests.
 */
struct _fp_ts_test
{
	unsigned short port;
};

struct _fp_category
{
	unsigned char n_tests;
	size_t size;  /* total size of bytes for results of this category */
	struct _fp_ts_test tests[32];
};

/*
 * If you change this you also want to change the 2 bit's in
 * struct _state_fp
 */
#define FP_CAT_TCP	0x00
#define FP_CAT_UDP	0x01
#define FP_CAT_BANNER	0x02
#define FP_CAT_WWW	0x03
#define FP_CAT_SNMP	0x04
#define FP_CAT_NVT	0x05
#define FP_CAT_SMB	0x06  /* RESERVED */
#define FP_CAT_RES3	0x07  /* RESERVERD */
#define FP_CAT_MAX	0x08  /* change state.h if exceeded */

/*
 * The performed tests are dynamic and read form the thcrut-os-fingerprints
 * file. The access to the results of the tests is thus also
 * dynamic.
 */
struct _fp_testsuite
{
	int ofs_test_tcp;
	int ofs_test_udp;
	int ofs_test_banner;
	int ofs_test_www;
	int ofs_test_snmp;
	int ofs_test_nvt;
	unsigned char  n_tests; /* Total number of different tests in fp-file */
	struct _fp_category cat[6];

	char *strings;
	struct _fp *fps;  /* Linked list of Fingerprints */
};
/*
 * Required size for the results of the unique tests.
 */
#define FP_WTEST_SZ     (64)   /* HEAD / test output  */
#define FP_BTEST_SZ	(128)  /* Banner test         */
#define FP_STEST_SZ	(128)  /* SNMP test           */
#define FP_NTEST_SZ	(128)  /* NVT Terminal        */

struct _fp_nodequery
{
	unsigned short trans_id;
	unsigned short flags;
	unsigned short questions;
	unsigned short answers;
	unsigned short auth_rrs;
	unsigned short add_rrs;
};

/*
 * Right now all variables are stored lineary.
 * We do not expect to have more than 50
 */
struct _fp_vararray
{
	unsigned short ofs_varname;
	char accuracy;
	struct _fp_tests *tests;    /* Linked list of Tests for this Varname */
};

/*
 * Windows NODE query request (port 137).
 * How dirty to use a static request but it never changes unless
 * MS decides to change their protocol suite. This wont happen :>
 */
#define FP_NODEQUERY "\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
#define FP_NODEQUERY_LEN (38)

/*
 * WIndows DCE bind request.
 */
#define FP_DCEBIND "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa\x03\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00"
/* It is actually enough to send 1 byte of payload to trigger windows for a
 * reject packet.
 */
#define FP_DCEBIND_LEN (50)

/*
 * SNMP 'public' GET-NEXT system.sysDescr.0
 */
#define FP_SNMP "\x30\x82\x00\x27\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa1\x1a\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0f\x30\x82\x00\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x00\x05\x00"
#define FP_SNMP_LEN (43)

#define FP_MAX_LEN (50)

union _classid
{
	struct
	{
#if LIBNET_BIG_ENDIAN
		unsigned int genre:9;
		unsigned int vendor:6;
		unsigned int os:5;
                /* 9 + 6 + 5 = 20 bits */
		unsigned int d:4;
		unsigned int dd:4;
		unsigned int ddd:4;
#elif LIBNET_LIL_ENDIAN
		unsigned int ddd:4;
		unsigned int dd:4;
		unsigned int d:4;
                /* 9 + 6 + 5 = 20 bits */
		unsigned int os:5;
		unsigned int vendor:6;
		unsigned int genre:9;
#endif
	} st;
	unsigned int id;
};
	

int FP_TS_load(struct _fp_testsuite *fpts, const char *filename);
void FP_TS_dump(struct _fp_testsuite *fpts);
char *FP_class2str(char *dst, unsigned int val);
unsigned int FP_class2int(const char *input);

#endif /* !__THCRUT_FP_H__ */
