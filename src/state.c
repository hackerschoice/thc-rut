/*
 * $Id: state.c,v 1.13 2003/05/25 18:19:16 skyper Exp $
 *
 * ChangeLog
 * - added variable length state support (struct _state_* ).
 */


#include "default.h"
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "state.h"

#define STATE_HASH(sq, ip) (ntohl(ip) & (sq)->hash_entry_mask)
// FIXME: debugging
//#define STATE_HASH(sq, ip) 0


static	fd_set g_rfds;

/*
 * Initialize a state queue
 */
#define BIT_HASH    (10)
struct _state_queue *
SQ_init(struct _state_queue *sq, unsigned long nitems, size_t item_size, int fd, cb_timeout_t cb_timeout, cb_filter_t cb_filter)
{
	int size;

	item_size = (item_size + 3) & ~3; /* Align to 4 bytes */

	if (nitems > 500000)
		nitems = 500000;
	sq->epoch = 1000000 / nitems; /* length of on epoch in ms */

	size = nitems * item_size + (1 << BIT_HASH) * sizeof(struct _state *);
	/* Hash size must be one of 2^n */
	sq->hash_entry_mask = (1 << BIT_HASH) - 1;
	sq->n_entries = nitems;
	sq->current = 0;
	sq->item_size = item_size;
	sq->cb_timeout = cb_timeout;
	sq->cb_filter = cb_filter;
	sq->fd = fd;

	sq->hash = malloc(size); //shmat(sq->shmid, NULL, 0);
	if (!sq->hash)
		return NULL;
	memset(sq->hash, 0, size);
	sq->queue = (struct _state *)(sq->hash + (1 << BIT_HASH));

	gettimeofday(&sq->expect, NULL);

	DEBUGF("entries: %ld\n", sq->n_entries);
	DEBUGF("item_size: %u\n", sq->item_size);
	DEBUGF("epoch: %ld usec\n", sq->epoch);

	return sq;
}

void
STATE_deinit(struct _state_queue *sq)
{
	XFREE(sq->hash);
#if 0
	if (sq->shmid)
		shmctl(sq->shmid, IPC_RMID, 0);
	sq->shmid = 0;
#endif
}

/*
 * IP is in NBO
 */
struct _state *
STATE_by_ip(struct _state_queue *sq, uint32_t ip)
{
	struct _state *state = sq->hash[STATE_HASH(sq, ip)];
	int i = 0;

	while (state)
	{
		i++;
		if ((state->ip == ip) && (STATE_current(state)))
			break;
		state = state->next;
	}

	return state;
};

/*
 * Only called by sending process
 *
 * One might think that here is a race condition, but
 * this wrong: The element we unlink is the last element of
 * the hash list. New elements are always inserted at the top.
 * The last one is thus the oldest. Relinking becomes
 * very easy as we only have to set the next pointer of the previous
 * item to NULL (to make it become the last).
 */
void
STATE_link(struct _state_queue *sq, struct _state *state)
{
	unsigned int idx;

	idx = STATE_HASH(sq, state->ip);

	/* Link */
	state->prev = NULL;
	state->next = sq->hash[idx];
	if (state->next)
		state->next->prev = state;

	sq->hash[idx] = state;
}

void
STATE_unlink(struct _state_queue *sq, struct _state *state)
{
	unsigned int idx;

	if (state->prev == NULL)
	{
		if (state->ip == 0)
			return; /* Not linked at all! */
		idx = STATE_HASH(sq, state->ip);
		sq->hash[idx] = state->next; /* NULL usually */
	} else
		state->prev->next = state->next; /* NULL usually */

	/* 
	 * We dont need this if we would always remove the last element.
	 * We actually dont do this any longer...
	 */
	if (state->next)
		state->next->prev = state->prev;
}


/*
 * FIXME: we must check if n_inuse dropped to 0.
 * Otherwise we might spin-loop in the while loop up
 * until 1 second (does thismatter?)
 *
 * FIXME: also, we dont have to call gettimofday()
 * if we only wait some very short fragment of time
 * or have just been called with tv_(u)sec = 0 to check
 * if the FD is set (but without sleeping).
 */
/*
 * FREEBSD-BPF-SELECT-BUG:
 * http://www.tcpdump.org/lists/workers/2001/05/msg00060.html
 * The flag that data is ready to read is only set when the internal
 * kernel buffer overflows.
 * We call cb_filter even if select does not indicate that there is something
 * to read. We still call select() in case the internal buffer overflows on
 * long delays (like 0.9999 seconds).
 *
 * Solution: It actually works under FreeBsd 4.6-RC6 if pcap_open_live
 * is initialized with ms > 0.
 */
/*
#ifdef THCRUT_BROKEN_BPF_SELECT
# define SQ_WHILE_LOOP(diff)	do { \
	FD_SET(sq->fd, &g_rfds); \
	select(sq->fd + 1, &g_rfds, NULL, NULL, &diff); \
	sq->cb_filter(); \
	gettimeofday(&now, NULL); \
	SQ_TV_diff(&diff, &now, &sq->expect); \
} while (diff.tv_usec >= 0)
#else
*/
/*
 * NOTE: pcap manual page (escpecially for linux) does not match
 * the implementation. Current implementation always only process
 * one package. We have to check on our own if there are other remaining
 * packets to be read. There are two ways to do so:
 * - 1.1 use non-blocking pcap-fd and call cb_filter until 0 is returned.
 * - 1.2 call select() again with 1 ms even if time (diff) is already up.
 * On !LINUX can we assume that all packets have been read if <= 1
 * is returned (because those OS'es would have read more than 1 packet
 * if available.
 *
 * FIXME: what's faster, 1.1 or 1.2?
 */
#define SQ_WHILE_LOOP(diff)	do { \
		FD_SET(sq->fd, &g_rfds); \
		ret = select(sq->fd + 1, &g_rfds, NULL, NULL, &diff); \
		if (ret > 0) \
			sq->cb_filter(); \
		else if (ret == 0) \
			break; \
		else if (errno != EINTR) \
			break; \
		gettimeofday(&now, NULL); \
		SQ_TV_diff(&diff, &now, &sq->expect); \
		if (diff.tv_usec < 0) \
			diff.tv_usec = 0; \
} while (1)
/* } while (diff.tv_usec >= 0) */

static void
state_select(struct _state_queue *sq)
{
	struct timeval now, diff;
	static unsigned char min_select;
	int ret;

	gettimeofday(&now, NULL);
	SQ_TV_diff(&diff, &now, &sq->expect);
	//fprintf(stderr, "is %ld.%ld should %ld.%ld (%ld.%ld ms diff)\n", now.tv_sec, now.tv_usec, sq->expect.tv_sec, sq->expect.tv_usec, diff.tv_sec, diff.tv_usec);

	/*
	 * At least every n invokations go into select
	 */
	if (diff.tv_usec >= 0)
	{
		min_select = 0;
	} else if (min_select++ >= 5) {
		//DEBUGF("expect\n%d.%8.8d but it's already\n%d.%8.8d\n", sq->expect.tv_sec, sq->expect.tv_usec, now.tv_sec, now.tv_usec);
		diff.tv_usec = 0;
		min_select = 0;
	} else
		return;

	SQ_WHILE_LOOP(diff);
}

/*
 * SQ must be init first
 * FIXME: determine when to exit.
 * - Set STATE_reset decrement n_inuse and check in select loop
 *   if it dropped to 0.
 *
 * Function returns when a new IP is required.
 * OpenBSD: Sniffed packets are not available in realtime.
 * (pcap fd does not indicate that data is available).
 * There is a delay of around 1 second. FIXME: Why???
 */
int
STATE_wait(struct _state_queue *sq, const struct _state *nextstate)
{
	struct _state *state;

	SQ_next(state, sq);

	//DEBUGF("current %u, nextstate %p use: %d\n", STATE_current(state), nextstate, sq->n_inuse);
start:
	if (!STATE_current(state))
	{
fillagain:
		/* Fill a state with new target */
		if (nextstate)
		{
			STATE_unlink(sq, state);
	 		memcpy(state, nextstate, sq->item_size);
			STATE_link(sq, state);
			//DEBUGF("FIXME Fist invokation of dis_timeout at %ld\n", sq->current);
			sq->cb_timeout(state);
//			sq->reschedule = 0;
			/* n_inuse = max because we check on next call 
			 * inside the while(1) loop (sq->n_inuse--)
			 */
			/* Didnt switched state? */
			if (state->current)
				sq->n_inuse = sq->n_entries;
			SQ_TV_add(&sq->expect, sq->epoch);
			state_select(sq);
			return 0;
		} else {
			/*
			 * Scroll through all free and unused slots so
			 * that select() is only called once for all
			 * unused slots in a row.
			 */
			while (1)
			{
				sq->n_inuse--;
				if (sq->n_inuse <= 0)
					return -1;   /* FINISHED */
				SQ_TV_add(&sq->expect, sq->epoch);
				SQ_next(state, sq);
				if (STATE_current(state))
					break;
			}
			state_select(sq);
			/* state-content might have changed while receiving
			 * packets. Check again if still active.
			 */
			goto start;
		}
	} else { /* Current state is set and waited 1 sec */
		sq->n_inuse = sq->n_entries;
		if (state->reschedule)
		{
			state->reschedule = 0;
			SQ_TV_add(&sq->expect, sq->epoch);
			state_select(sq);
			SQ_next(state, sq);
			goto start;
		} else {
			sq->cb_timeout(state);
//			sq->reschedule = 0;
			/*
			 * State empty, everything processed
			 */
			if ((!state->current) && (nextstate == NULL) && (sq->n_inuse <= 1))
			{
				fflush(stdout);
				return -1;
			}
			/*
			 * Instantly reused if a slot became free.
			 * Otherwise put it back and sniff a round.
			 */
			if (state->current)
			{
				SQ_TV_add(&sq->expect, sq->epoch);
				state_select(sq);
				SQ_next(state, sq);
				goto start;
			}
			goto fillagain;
		}
	}

	return -1; /* Not reached */
}

