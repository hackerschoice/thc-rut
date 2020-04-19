/*
 * $Id: state.h,v 1.9 2003/05/25 18:19:16 skyper Exp $
 */

#ifndef __THCRUT_STATE_H__
#define __THCRUT_STATE_H__ 1

#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>

/*
 * 12 bytes state entry
 * at 10,000 PPS * 3 sec * 12 bytes = 360k
 *
 * TODO:
 * Optimisaztion: next and prev dont have to be full 4byte/8byte pointer.
 * We can use idx into the queue table.
 */
struct _state
{
	struct _state *next;  /* hash */
	struct _state *prev;  /* hash */
	unsigned int ip;  /* HBO */
	unsigned char current:7;  /* Up to 32 different states */
	unsigned char reschedule:1;  /* Up to 15 seconds delay */
	/*
	 * What a pity, we waste 3 bytes of memory here.
	 * Can merge reschedule flag with ip and move current to
	 * _state_fp.
	 */
};

typedef void (*cb_timeout_t)(struct _state *);
typedef void (*cb_filter_t)(void);

struct _state_queue
{
	struct _state *queue;
	struct _state **hash;
	int shmid;
	int hash_entry_mask;
	char hash_fix;
	long current;
	long n_entries;
	int n_inuse;
	size_t item_size;  /* size of struct _state_* */
	struct timeval expect;
	long epoch;  /* length of an epoche in ms */
	unsigned char *packet;
	int fd;   /* pcap_fd */
	fd_set rfds;
	int max_fd;
	cb_timeout_t cb_timeout;
	cb_filter_t cb_filter;
};

#define SQ_FD_set(myfd, sq)  do{ \
	FD_SET(myfd, (sq)->rfds); \
	if ((sq)->max_fd < myfd) \
		(sq)->mac_fd = myfd; \
}while(0)

#define SQ_step(sq) do{ \
	(sq)->current++; \
	if ((sq)->current >= (sq)->n_entries) \
		(sq)->current = 0; \
}while(0)

#define SQ_next(state, sq) do{ \
	SQ_step(sq); \
	(state) = (struct _state *)((char *)(sq)->queue + (sq)->item_size * (sq)->current); \
}while(0)

#define SQ_current(state, sq) (state) = &(sq)->queue[(sq)->current]
/*
 * STATE_switch() should be used if a state switches and
 * rescheduling is required.
 * STATE_current(state) = NEW STATE should be used otherwise.
 */
#define STATE_reschedule(state, val)  ((struct _state *)(state))->reschedule = val
#define STATE_switch(state, val) do{((struct _state *)(state))->current = val; if (val) ((struct _state *)(state))->reschedule = 1; else ((struct _state *)(state))->reschedule = 0; }while(0)
#define STATE_reset(state)  ((struct _state *)(state))->current = 0;
#define STATE_ip(state)   ((struct _state *)(state))->ip
#define STATE_current(state) ((struct _state *)(state))->current

#define SQ_TV_add(tv, usec) do{ \
	(tv)->tv_usec += usec; \
	if ((tv)->tv_usec >= 1000000) \
	{ \
		(tv)->tv_usec -= 1000000; \
		(tv)->tv_sec++; \
	} \
}while(0)

/* Calculate the difference from small to large */
#define SQ_TV_diff(dst, small, large) do{ \
	if ((small)->tv_sec > (large)->tv_sec) \
	{ \
		(dst)->tv_sec = 0; \
		(dst)->tv_usec = -1; \
		break; \
	} \
	(dst)->tv_sec = (large)->tv_sec - (small)->tv_sec; \
	if (((dst)->tv_sec == 0) && ((small)->tv_usec > (large)->tv_usec)) \
	{ \
		(dst)->tv_sec = 0; \
		(dst)->tv_usec = -1; \
		break; \
	} \
	(dst)->tv_usec = (large)->tv_usec - (small)->tv_usec; \
	if ((dst)->tv_usec < 0) \
	{ \
		(dst)->tv_sec--; \
		(dst)->tv_usec = 1000000 + (dst)->tv_usec; \
	} \
}while(0)


struct _state_queue *SQ_init(struct _state_queue *sq, unsigned long nitems, size_t item_size, int fd, cb_timeout_t cb_timeout, cb_filter_t cb_filter);
void STATE_deinit(struct _state_queue *sq);
void STATE_link(struct _state_queue *sq, struct _state *state);
void STATE_unlink(struct _state_queue *sq, struct _state *state);
struct _state *STATE_by_ip(struct _state_queue *sq, unsigned int ip);
int STATE_wait(struct _state_queue *sq, const struct _state *nextstate);

#endif /* !__THCRUT_STATE_H__ */
