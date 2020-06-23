#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "exif.h"
#include "file.h"
#include "logging.h"

/*
 * TODO
 *	Add option for user to rename the image file using exif data.
 *	E.g., img.jpg => 20200620_213028_Canon_PowerShot_SX160_IS.jpg
 */

static int get_options(int, char *[]) __wur;
static void usage(int) __attribute__((__noreturn__));
//static void print_logo(void);

int
main(int argc, char *argv[])
{
	int fd;
	unsigned char *p = NULL;
	struct stat statb;
	void *data = NULL;
	int endianness;
	//int cnt;

	prog_name = argv[0];

	if (get_options(argc, argv) < 0)
		goto fail;

	if (!file_ok(argv[1]))
		goto fail;

	//print_logo();

	clear_struct(&statb);
	lstat(argv[1], &statb);

	infile.size = statb.st_size;

#if 0
	fprintf(stdout, "\e[38;5;19m  File: %s%s"
			"  Size: %lu bytes%s"
			"  Opts: %s%s%s%s%s%s%s%s"
			"\e[m",
			argv[1], _EOL,
			statb.st_size, _EOL,
			!FLAGS ? "None" : "",
			FLAGS & WIPE_ALL ? "Wipe all " : "",
			FLAGS & WIPE_DATE ? "Wipe date " : "",
			FLAGS & WIPE_DEVICE ? "Wipe device " : "",
			FLAGS & WIPE_UID ? "Wipe UID " : "",
			FLAGS & WIPE_COMMENT ? "Wipe Comment " : "",
			_EOL, _EOL);
#endif

	fd = open(argv[1], O_RDWR);

	assert(strlen(argv[1]) < MAX_PATH_LEN);
	strncpy(infile.fullpath, argv[1], strlen(argv[1]));
	infile.fullpath[strlen(argv[1])] = 0;
	infile.fd = fd;
	
	if ((data = mmap(NULL, statb.st_size, PROT_READ, MAP_SHARED, fd, 0)) == MAP_FAILED)
		goto fail;

	infile.map = data;
	infile.map_end = ((unsigned char *)data + statb.st_size);
	infile.new_end = infile.map_end;

	lim = get_limit(&infile);
	if (!lim)
	{
		log_error("Failed to find limit");
		goto fail;
	}

#ifdef DEBUG
	printf("Size of exif data: %lu bytes\n", (lim - infile.map));
#endif

	p = (unsigned char *)data;
	while (strncmp("Exif", (char *)p, 4) != 0 && p < (unsigned char *)infile.map_end)
		++p;
	if (p == (unsigned char *)infile.map_end)
	{
		fprintf(stdout, "No EXIF data in %s\n", argv[1]);
		goto end;
	}

	while (strncmp((char *)"MM", (char *)p, 2) != 0
			&& strncmp((char *)"II", (char *)p, 2) != 0
			&& p < ((unsigned char *)data + statb.st_size))
		++p;

	EXIF_DATA_OFFSET = (off_t)(p - (unsigned char *)data);

	if (p == ((unsigned char *)data + statb.st_size))
	{
			errno = EPROTO;
			log_error("No endianness marker in file");
			goto fail;
	}
	else
	if (strncmp((char *)"MM", (char *)p, 2) == 0)
		endianness = 1;
	else
		endianness = 0;

	fprintf(stdout, "\n** %s **\n\n", infile.fullpath);

	int n = extract_data(&infile, (const int)endianness);
	fputc('\n', stdout);

	if (0 == n)
		fprintf(stderr, "    No exif data\n\n");
#if 0
	fprintf(stdout, "\e[38;5;8m  ----------------EXIF Data----------------\e[m%s%s", _EOL, _EOL);

	/* Date and time data */
	fprintf(stdout, "%s\tDate/Time Data\e[m%s", SECTION_COL, _EOL);
	cnt = get_date_time(&infile, (const int)endianness);
	if (!cnt)
		printf(" (None)%s", _EOL);

	/* GPS data */
	fprintf(stdout, "%s%s\tGPS Data\e[m%s", _EOL, SECTION_COL, _EOL);
	cnt = get_gps_data(&infile, (const int)endianness);
	if (!cnt)
		printf(" (None)%s", _EOL);

	/* Device / software data */
	fprintf(stdout, "%s%s\tDevice Data\e[m%s", _EOL, SECTION_COL, _EOL);

	cnt = get_make_model(&infile, (const int)endianness);
	if (!cnt)
		printf(" (None)%s", _EOL);

	/* Miscellaneous data */
	fprintf(stdout, "%s%s\tMisc Data\e[m%s", _EOL, SECTION_COL, _EOL);
	cnt = get_miscellaneous_data(&infile, (const int)endianness);
	if (!cnt)
		printf(" (None)%s", _EOL);
#endif

end:
	if (data)
	{
		munmap(data, statb.st_size);
		data = NULL;
	}
	exit(EXIT_SUCCESS);

fail:
	if (data)
	{
		munmap(data, statb.st_size);
		data = NULL;
	}
	exit(EXIT_FAILURE);
}

int
get_options(int argc, char *argv[])
{
	int					i;

	FLAGS = 0;

	for (i = 1; i < argc; ++i)
	{
		if (!strcmp("--date", argv[i]))
		{
			++i;
			if (i >= argc)
			{
				fprintf(stderr, "--date requires one or more arguments\n");
				goto fail;
			}

			int j = i;
			char *p = NULL;
			char *q = argv[j];
			char *e = (argv[j] + strlen(argv[j]));

			while (p < e)
			//while (j < argc && argv[j][0] != '-')
			{
				p = memchr(q, ',', (e - q));
				if (!p)
					p = e;
			}
		}
		if (strncmp("--help", argv[i], 6) == 0)
			usage(EXIT_SUCCESS);
		else
		if (strcmp("--wipe-sensitive", argv[i]) == 0)
			FLAGS |= WIPE_SENSITIVE;
		else
		if (strcmp("--fake-dates", argv[i]) == 0)
		{
			FLAGS |= FL_FAKE_DATES;
		}
	}

	return 0;

fail:
	return -1;
}

void
usage(int exit_type)
{
	fprintf(stdout,
		"Exifer usage\n\n"
		"exifer <image> [options]\n"
		"\n"
		"  --wipe-sensitive    Wipe sensitive exif data, such as\n"
		"                      times and dates, location information,\n"
		"                      camera model/manufacturer, serial numbers\n"
		"                      and unique image/camera IDs\n");

	exit(exit_type);
}

#if 0
#define LINE_COL		"\e[38;5;232m"
#define VERSION_COL	"\e[38;5;124m"
#define BANNER_COL	"\e[38;5;208m"

void
print_logo(void)
{
	fprintf(stdout,
				"\n"
				"%s  ##########################################################################################################################\e[m\n"
				"%s                                                                                                                               \e[m\n"
				"%s    ############   ####       ####    ####      #############      ####   ####   ####   ####   ############     ###########    \e[m\n"
				"%s   ##############   ####     ####    ######    ############        ####   ####   ####  ######  #############   #############   \e[m\n"
				"%s  #####     #####    ####   ####      ####     ####                ####   ####   ####   ####   ####     ####  #####    #####   \e[m\n"
				"%s  #####     #####     #### ####                ####                ####   ####   ####          ####     ####  #####    #####   \e[m\n"
				"%s  ###############      ########       ####   ###############       ####   ####   ####   ####   ############   ##############   \e[m\n"
				"%s  ##############      #### ####       ####   #############         ####   ####   ####   ####   ###########    #############    \e[m\n"
				"%s  #####              ####   ####      ####     ####                ####   ####   ####   ####   ####           #####            \e[m\n"
				"%s  #####             ####     ####     ####     ####                ####   ####   ####   ####   ####           #####            \e[m\n"
				"%s   ##############  ####       ####    ####     ####                 ####  ####  ####    ####   ####            #############   \e[m\n"
				"%s    ############  ####         ####   ####     ####                  ##############     ####   ####             ###########    \e[m\n"
				"%s                                                                                                                               \e[m\n"
				"%s  %sversion %s\e[m%s                                                                                                                \e[m\n"
				"%s  ##########################################################################################################################\e[m\n"
				"\n"
				"\n",
				LINE_COL,
				BANNER_COL,
				BANNER_COL,
				BANNER_COL,
				BANNER_COL,
				BANNER_COL,
				BANNER_COL,
				BANNER_COL,
				BANNER_COL,
				BANNER_COL,
				BANNER_COL,
				BANNER_COL,
				BANNER_COL,
				BANNER_COL,
				VERSION_COL,
				BUILD,
				BANNER_COL,
				LINE_COL);

	return;
}
#endif
