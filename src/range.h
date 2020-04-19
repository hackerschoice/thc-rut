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
/*
#define IP_next(ipr) do{ \
	char *ptr; \
	char *split; \
	char buf[16]; \
	unsigned char len; \
	unsigned char splitc; \
	unsigned char n; \
	if ((ipr)->used >= (ipr)->end_ip - (ipr)->start_ip) \
	{ \
		if ((ipr)->next == NULL) \
		{ \
			(ipr)->current_ip = 0; \
			(ipr)->end_ip = 0; \
			break; \
		} \
		while (*(ipr)->next == ' ') \
			(ipr)->next++; \
		ptr = (ipr)->next; \
		split = NULL; \
		(ipr)->ofs = 0; \
		(ipr)->used = 0; \
		while (1) \
		{ \
			if (*(ipr)->next == '-') \
				split = (ipr)->next; \
			if (*(ipr)->next == '/') \
				split = (ipr)->next; \
			if (*(ipr)->next == ',') \
				break; \
			if (!*(ipr)->next) \
				break; \
			(ipr)->next++; \
		} \
		if (split) \
		{ \
			len = MIN(sizeof buf - 1, split - ptr); \
			memcpy(buf, ptr, len); \
			buf[len] = '\0'; \
			splitc = *split; \
			(ipr)->start_ip = ntohl(inet_addr(buf)); \
			split++; \
			while (*split == ' ') \
				split++; \
			if (*(ipr)->next) \
			{ \
				len = MIN(sizeof buf - 1, (ipr)->next - split); \
				memcpy(buf, split, len); \
				buf[len] = '\0'; \
				split = buf; \
			} \
			(ipr)->end_ip = ntohl(inet_addr(split)); \
			if (splitc == '/') \
			{ \
				n = (ipr)->end_ip; \
				if ((n > 30) || (n == 0)) \
					n = 32; \
				(ipr)->start_ip &= ~((1 << (32 - n)) - 1); \
				(ipr)->end_ip = (ipr)->start_ip + (1 << (32 - n)) - 1; \
				if (n <= 30) \
				{ \
					(ipr)->start_ip++; \
					(ipr)->end_ip--; \
				} \
			} else if ((ipr)->end_ip < (ipr)->start_ip) \
				(ipr)->end_ip = (ipr)->start_ip + (ipr)->end_ip - 1; \
		} else { \
			if (*(ipr)->next) \
			{ \
				len = MIN(sizeof buf - 1, (ipr)->next - ptr); \
				memcpy(buf, ptr, len); \
				buf[len] = '\0'; \
				ptr = buf; \
			} \
			(ipr)->start_ip = ntohl(inet_addr(ptr)); \
			(ipr)->end_ip = (ipr)->start_ip; \
		} \
		(ipr)->current_ip = (ipr)->start_ip; \
		(ipr)->distance = ((ipr)->end_ip - (ipr)->start_ip) >> 2; \
		if ((ipr)->distance <= 0) \
			(ipr)->distance = 1; \
		else if ((ipr)->distance > 259) \
			(ipr)->distance = 259; \
		if (*(ipr)->next == '\0') \
		{ \
			(ipr)->argv++; \
			(ipr)->next = (ipr)->argv[0]; \
		} else \
			(ipr)->next++; \
	} else { \
		(ipr)->current_ip += (ipr)->distance; \
		(ipr)->used++; \
		if ((ipr)->current_ip > (ipr)->end_ip) \
			(ipr)->current_ip = (ipr)->start_ip + ++(ipr)->ofs; \
	} \
	(ipr)->tot_used++; \
}while(0)
*/

#define IP_range_init(ipr) do { \
	(ipr)->used = 0; \
	(ipr)->ofs = 0; \
	(ipr)->next_ip = (ipr)->range->start; \
	(ipr)->distance = ((ipr)->range->end - (ipr)->range->start) >> 2; \
	if (((ipr)->mode != IPR_MODE_SPREAD) || ((ipr)->distance <= 0)) \
		(ipr)->distance = 1; \
	else if ((ipr)->distance > 259) \
		(ipr)->distance = 259; \
} while (0)

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

#endif /* !THCRUT_RANGE_H */
