#ifndef THCRUT_RANGE_H
#define THCRUT_RANGE_H 1

#ifndef ETH_ALEN
#define ETH_ALEN               6
#endif


struct _iprange
{
	unsigned int start;
	unsigned int end;
};

struct _ipranges
{
	char **argv;
	char *next;
	unsigned int start_ip;
	unsigned int end_ip;
	unsigned int current_ip;
	unsigned int next_ip;
	struct _iprange *data;
	struct _iprange *range;	/* Current range */
	unsigned char mode;
	/* Those for spread scan mode */
	unsigned int ofs;
	unsigned int used;
	unsigned int distance;
	/* For stats */
	unsigned int tot_used;
	unsigned int total;
	char buf[16];
};

#define IP_current(ipr)  (ipr)->current_ip
#define IP_end(ipr)    (((ipr)->argv[0] == NULL) && ((ipr)->current_ip >= (ipr)->end_ip))
/* Modes for ip range initialization */
#define IPR_MODE_SPREAD		(0x01)

/*
 * Started as a small while loop in a define, growed over time.
 * Put this in a function further or later..
 *
 * Function breaks down ,-seperated strings in **argv into chunks.
 * Each chunk represents a IP or IP-range of the form:
 * a.b.c.d
 * a.b.c.d-x.y.z.
 * a.b.c.d-n
 *
 * IP's are returned in a non-sequential order to avoid arp flooding of a
 * target network (flooded by the arp-who-has of the first router).
 *
 * The algorithm is easy:
 * Increment +1 how many ip's have already been taken from the range.
 * Break out if this value >= end_ip - start_ip.
 * Increment the last ip by a fixed value.
 * Reset to start_ip + ofs_base if the new ip is larger then the end_ip and
 * increment ofs_base by +1.
 */

#define IP_next(ipr) do { \
	if ((ipr)->used > (ipr)->range->end - (ipr)->range->start) \
	{ \
		(ipr)->range++; \
		if (!(ipr)->range->start) \
		{ \
			(ipr)->current_ip = 0; \
			break; \
		} \
		IP_range_init(ipr); \
	} \
	(ipr)->current_ip = (ipr)->next_ip; \
	(ipr)->next_ip += (ipr)->distance; \
	if ((ipr)->next_ip > (ipr)->range->end) \
		(ipr)->next_ip = (ipr)->range->start + ++(ipr)->ofs; \
	(ipr)->used++; \
	(ipr)->tot_used++; \
} while(0)


void IP_init(struct _ipranges *ipr, char *argv[], unsigned char mode);
void IP_range_init(struct _ipranges *ipr);
void IP_reset(struct _ipranges *ipr);

#endif /* !THCRUT_RANGE_H */
