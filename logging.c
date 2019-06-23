#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "exif.h"
#include "logging.h"

void
log_error(const char *fmt, ...)
{
	int 			save;
	char			tmp[1024];
	va_list		args;

	save = errno;
	va_start(args, fmt);
	vsprintf(tmp, fmt, args);
	fprintf(stderr, "\e[38;5;9m[-] %s (%s)\e[m%s", tmp, strerror(save), _EOL);
	va_end(args);
	errno = save;
	return;
}
