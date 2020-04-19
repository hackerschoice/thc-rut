/*
 * $Id:$
 */

#include "default.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <termios.h>
#include "tty.h"

static struct termios saved_ti;
static char hasbeenset;

/*
 * Assign 0x20 (space key) to cause a SIGQUIT.
 */
void
tty_init(void)
{
	int fd;
	struct termios ti;

	fd = open("/dev/tty", O_RDONLY);
	if (fd < 0)
		return;
	tcgetattr(fd, &ti);
	memcpy(&saved_ti, &ti, sizeof saved_ti);
	ti.c_cc[VQUIT] = 0x20; /* hitting spaces causes SIGQUIT */
	tcsetattr(fd, TCSANOW, &ti);
	hasbeenset = 1;
	atexit(tty_dinit);
	close(fd);
}

void
tty_dinit(void)
{
	int fd;
	
	if (!hasbeenset)
		return;

	fd = open("/dev/tty", O_RDONLY);

	if (fd < 0)
		return;
	
	tcsetattr(fd, TCSANOW, &saved_ti);
	close(fd);
	hasbeenset = 0;
}

