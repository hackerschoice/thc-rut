/*
 * $Id: thcrut_sig.c,v 1.1 2002/11/22 18:54:49 skyper Exp $
 */

#include "default.h"
#include <sys/types.h>
#include <signal.h>
#include "thc-rut.h"

static void sigparent_handler(int sig);

extern struct _opt opt;

void
signal_parent_init(void)
{
	signal(SIGTERM, sigparent_handler);
	signal(SIGINT, sigparent_handler);
	signal(SIGQUIT, sigparent_handler);
	signal(SIGCHLD, sigparent_handler);
}

void
signal_child_init(void)
{
	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
}

/*
 * Only one process should destroy the shm.
 */
static void
sigparent_handler(int sig)
{
	if ((opt.childpid) && (sig == SIGTERM))
		kill(opt.childpid, SIGTERM);

	STATE_deinit(&opt.sq);
	_exit(0);
}

