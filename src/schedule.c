#include "default.h"
#include "schedule.h"

/*
 * reset the schedule-struct
 * return 0 on success
 */
int
reset_schedule(struct _schedule *sd)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        return -1;

    sd->tv1.tv_sec = tv.tv_sec - 100;
    sd->tv1.tv_usec = tv.tv_usec;
    sd->tps = sd->ps * 100;
    
    return 0;
}

/*
 * init a schedule structure...make it start
 * 10 seconds in the past.
 * return 0 on success
 */
int
init_schedule(struct _schedule *sd, int ps)
{
    sd->ps = ps;
    sd->sps = sd->ps;

    return reset_schedule(sd);
}

/*
 * usleep until its time for this process
 * (eg as soon as it drops < ps)
 */
int
wait_schedule(struct _schedule *sd)
{
	struct timeval tv;
	float sec;

	if (!(sd->ps > 0))
		return 0;       /* no delay at all */

	/* FIXME: Use a long long int here */
	/* FIXME: horrible what i did here :> */
	/* Better sleep as many seconds until it's our turn again */
	while (1)
	{
		if (gettimeofday(&tv, NULL) != 0)
			return -1;

        sec = (tv.tv_sec - sd->tv1.tv_sec)
            - (sd->tv1.tv_usec - tv.tv_usec) / 1000000.0;
        if ( (sd->tps / sec) >= sd->ps)
            usleep(40);     /* should give up timeslice */
        else
            break;
    }

    if (sd->tps++ == -1)       /* if total per seconds overflow */
        reset_schedule(sd);

    return 0;
}

/*
 * speedup < 1 will slow down
 * and > 1 will speedup everything.
 * returns the speedup that was successfully assigned
 * to the scheduler.
 * < 0 on error.
 */
int
ctrl_schedule(struct _schedule *sd, float speedup)
{
    struct timeval tv;

    if (speedup > 10)
        speedup = 10;

    if (speedup < 0.1)
        speedup = 0.1;

    if (speedup == 0)
        return 0;

    if (gettimeofday(&tv, NULL) != 0)
        return -1;

    sd->ps = sd->ps * speedup;
    sd->tv1.tv_sec = tv.tv_sec - (tv.tv_sec - sd->tv1.tv_sec) / speedup;

    return speedup;
}

