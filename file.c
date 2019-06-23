#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "file.h"

int
file_ok(const char *const filename)
{
	if (access(filename, F_OK) != 0)
		{
			fprintf(stderr, "%s does not exist\n", filename);
			return 0;
	  }
	else
	if (access(filename, R_OK) != 0)
	  {
			fprintf(stderr, "Cannot read %s\n", filename);
			return 0;
	  }
	else
	if (access(filename, W_OK) != 0)
	  {
			fprintf(stderr, "Cannot write to %s\n", filename);
			return 0;
	  }
	else
		return 1;
}
