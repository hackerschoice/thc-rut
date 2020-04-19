#ifndef THCRUT_SCHEDULE_H
#define THCRUT_SCHEDULE_H 1

#ifdef HAVE_CONFIG_H
# if TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
# else
#  if HAVE_SYS_TIME_H
#   include <sys/time.h>
#  else
#   include <time.h>
#  endif
# endif
#else
# include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

struct _schedule
{
    struct timeval tv1;
    struct timeval tv2;
    unsigned short ps;  /* per second..sec is the smallest entity*/ 
                        /* this must by < tps / 10 ..._ALWAYS_  */
    unsigned short sps; /* saved per second. dont change this value. */
    unsigned long tps;  /* total per seconds since start...*/
};

int init_schedule(struct _schedule *, int);
int reset_schedule(struct _schedule *);
int wait_schedule(struct _schedule *);
int ctrl_schedule(struct _schedule *, float);

#endif /* !THCRUT_SCHEDULE_H */
