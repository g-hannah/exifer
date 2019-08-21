#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "exif.h"
#include "logging.h"

#define DATA_COL			"\e[38;5;88m"

static struct sigaction new_act, old_act;
static sigjmp_buf				__sigsegv__;

static void
sigsegv_handler(int signo)
{
	if (signo != SIGSEGV)
		return;
	else
		siglongjmp(__sigsegv__, 1);
}

static int
set_signal_handler(void)
{
	clear_struct(&new_act);
	clear_struct(&old_act);
	sigemptyset(&new_act.sa_mask);
	new_act.sa_handler = sigsegv_handler;
	new_act.sa_flags = 0;
	if (sigaction(SIGSEGV, &new_act, &old_act) < 0)
		return -1;
	else
		return 0;
}

#define setup_signal_handler() do { \
	set_signal_handler();																	\
	if (sigsetjmp(__sigsegv__, 1) != 0)										\
	{																											\
		log_error("Caught segmentation fault - exiting");		\
		exit(EXIT_FAILURE);																	\
	}																											\
} while (0)

static void
restore_signal_handler(void)
{
	if (sigaction(SIGSEGV, &old_act, NULL) < 0)
		log_error("Failed to restore old signal handler for SIGSEGV");

	return;
}

int
random_byte(unsigned char *c)
{
	int						fd;
	struct stat statb;
	ssize_t bytes = 0;
	int rv;

	clear_struct(&statb);

	if ((rv = lstat("/dev/urandom", &statb)) < 0)
	{
		perror("random_byte: lstat error\n");
		return -1;
	}

	if (unlikely(!S_ISCHR(statb.st_mode)))
	{
		perror("random_byte: /dev/urandom is not a special character file...\n");
		return -1;
	}

	if ((fd = open("/dev/urandom", O_RDONLY)) < 0)
	{
		perror("random_byte: failed to open /dev/urandom\n");
		return -1;
	}

	errno = EINTR;

	do
	{
		bytes = read(fd, c, 1);

		if (bytes < 0)
		{
			if (errno != EINTR)
			{
				perror("random_byte: failed to read a random byte from /dev/urandom\n");
				return -1;
			}
		}
		else
			break;

	} while (errno == EINTR);

	close(fd);

	return 0;
}

static void
wipe_data(file_t *file, datum_t *datum)
{
	unsigned char		*p = NULL;
	unsigned char		*s = NULL;
	unsigned char		*e = NULL;
	uint16_t				*u16 = NULL;
	uint32_t				*u32 = NULL;
	int							i;
	int							rv;

	p = s = (unsigned char *)datum->data_start;
	e = (unsigned char *)datum->data_end;

	if (mprotect(file->map, file->size, PROT_READ|PROT_WRITE) < 0)
	{
		perror("wipe_data: failed to set file map to PROT_READ|PROT_WRITE\n");
	}

	for (i = 0; i < 8; ++i)
	{
		unsigned char rc = 0;

		if ((rv = random_byte(&rc)) < 0)
		{
			fprintf(stderr, "Unable to %s overwrit%s exif data with pseudo-random data%s\n",
				!i ? "" : "finish",
				!i ? "e" : "ing",
				!i ? "-- just zeroing out" : "-- zeroing out");
			break;
		}

		while (p < e)
			*p++ = rc;
		p = s;
	}

	p = s;
	while (p < e)
		*p++ = 0;

	u16 = (uint16_t *)datum->tag_p;
	*u16 &= ~(*u16);
	u16 = (uint16_t *)datum->type_p;
	*u16 &= ~(*u16);
	u32 = (uint32_t *)datum->len_p;
	*u32 &= ~(*u32);
	u32 = (uint32_t *)datum->offset_p;
	*u32 &= ~(*u32);

	u32 = NULL;
	u16 = NULL;

	p = s = e = NULL;

	mprotect(file->map, file->size, PROT_READ);
	return;
}

static void *
exif_start(file_t *file)
{
	unsigned char *p = NULL;

	assert(file);
	assert(file->map);
	p = (unsigned char *)file->map;
	while (strncmp((char *)APP1_MARKER, (char *)p, 2) != 0 && p < (unsigned char *)file->map_end)
		++p;

	return (void *)p;
}

static void *
get_data_offset(file_t *file, datum_t *dptr, char *str, size_t slen, uint16_t type, int endian)
{
	unsigned char *p = NULL;
	unsigned char *t = NULL;

	assert(file);
	assert(dptr);
	assert(str);
	assert(lim > file->map);
	assert(file->new_end <= file->map_end);

	p = (unsigned char *)exif_start(file);
	t = (unsigned char *)str;

	clear_struct(dptr);

	while (memcmp(t, p, 2) && p < (unsigned char *)lim)
		++p;

	if (p == (unsigned char *)lim)
		return NULL;

	dptr->tag_p = (void *)p;
	dptr->type_p = (void *)((unsigned char *)p + 2);
	dptr->len_p = (void *)((unsigned char *)p + 4);
	dptr->offset_p = (void *)((unsigned char *)p + 8);

	if (endian)
	{
		uint32_t 	offset;
		uint32_t	len;
		uint16_t	type;
		uint8_t		*t = NULL;

		offset = *((uint32_t *)dptr->offset_p);
		t = (unsigned char *)&offset;
		if (*t == 0)
			offset = htonl(offset);
		dptr->offset = offset;

		len = *((uint32_t *)dptr->len_p);
		len = ntohl(len);
		t = (unsigned char *)&len;
		if (*t == 0)
			len = htonl(len);
		dptr->len = len;

		type = *((uint16_t *)dptr->type_p);
		type = ntohs(type);
		t = (unsigned char *)&type;
		if (*t == 0)
			type = ntohs(type);
		dptr->type = type;
		t = NULL;
	}
	else
	{
		uint32_t 	offset;
		uint32_t	len;
		uint16_t	type;
		uint8_t		*t = NULL;

		offset = *((uint32_t *)dptr->offset_p);
		t = (unsigned char *)&offset;
		if (*t == 0)
			offset = ntohl(offset);
		dptr->offset = offset;

		len = *((uint32_t *)dptr->len_p);
		t = (unsigned char *)&len;
		if (*t == 0)
			len = ntohl(len);
		dptr->len = len;

		type = *((uint16_t *)dptr->type_p);
		t = (unsigned char *)&type;
		if (*t == 0)
			type = ntohs(type);
		dptr->type = type;
		t = NULL;
	}

	if (dptr->offset >= (lim - file->map) || dptr->offset >= (file->map_end - file->map))
	{
		clear_struct(dptr);
		return NULL;
	}
	else
	{
		if ((dptr->type == TYPE_ASCII || dptr->type == TYPE_BYTE) && dptr->len <= 4)
			dptr->data_start = dptr->offset_p;
		else
			dptr->data_start = (void *)((unsigned char *)file->map + dptr->offset + EXIF_DATA_OFFSET);

		unsigned char *p = (unsigned char *)dptr->data_start;

		switch(type)
		{
			case TYPE_BYTE:
			case TYPE_ASCII:
			case TYPE_COMMENT:
			dptr->data_end = (void *)(p + dptr->len);
			break;
			case TYPE_SHORT:
			dptr->data_end = (void *)(p + (dptr->len * 2));
			break;
			case TYPE_SRATIONAL:
			case TYPE_RATIONAL:
			dptr->data_end = (void *)(p + (dptr->len * (sizeof(unsigned int) * 2)));
			break;
			default:
			dptr->data_end = (void *)(p + dptr->len);
		}

		p = NULL;
		return (void *)dptr;
	}
}

int
get_date_time(file_t *file, int endian)
{
	int								count;
	datum_t						datum;
	void							*p = NULL;

	setup_signal_handler();
	count = 0;

	p = get_data_offset(file, &datum, endian ? (char *)"\x90\x02" : (char *)"\x02\x90", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Digitised:",
					FLAGS & (WIPE_ALL | WIPE_DATE) ? "\e[9;02m" : "",
					DATA_COL,
					(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DATE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x90\x03" : (char *)"\x03\x90", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Original:",
				FLAGS & (WIPE_ALL | WIPE_DATE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DATE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x90\x04" : (char *)"\x04\x90", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Created:",
					FLAGS & (WIPE_ALL | WIPE_DATE) ? "\e[9;02m" : "",
					DATA_COL,
					(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DATE))
				wipe_data(file, &datum);
	}
	 
	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x32" : (char *)"\x32\x01", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Modified:",
					FLAGS & (WIPE_ALL | WIPE_DATE) ? "\e[9;02m" : "",
					DATA_COL,
					(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DATE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xc7\x1b" : (char *)"\x1b\xc7", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Preview:",
				FLAGS & (WIPE_ALL | WIPE_DATE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DATE))
			wipe_data(file, &datum); 
	}

	restore_signal_handler();

	return count;
}

int
get_gps_data(file_t *file, int endian)
{
	assert(file);

	datum_t		datum;
	void			*p = NULL;
	int				count;
	double		latitude_deg, latitude_min, latitude_sec;
	double		longitude_deg, longitude_min, longitude_sec;
	char			latitude_ref[16], longitude_ref[16];
	char			tmp_buf[256];
	unsigned int numerator, denominator;

	setup_signal_handler();
	count = 0;

#ifdef DEBUG
		fprintf(stderr, "Trying to get version...\n");
#endif
	p = get_data_offset(file, &datum, (char *)"\x00\x00", 2, TYPE_BYTE, endian);
	if (p && datum.type == TYPE_BYTE && datum.len == 4)
	{
		++count;

		char		*ptr = NULL;
		char		*tptr = NULL;
		unsigned char c;

		ptr = (char *)datum.data_start;
		tptr = tmp_buf;
		while (ptr < (char *)((char *)datum.data_start + (size_t)datum.len))
		{
			c = *ptr++;
			*tptr++ = (c + 0x30);
			*tptr++ = 0x2e;
		}

		--tptr;
		*tptr = 0;
		
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Version ID:",
					FLAGS & (WIPE_ALL | WIPE_GPS) ? "\e[9;02m" : "",
					DATA_COL,
					tmp_buf, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

#ifdef DEBUG
	fprintf(stderr, "Trying to get datestamp\n");
#endif
	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x1d" : (char *)"\x1d\x00", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		assert(datum.data_start);
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Datestamp:",
				FLAGS & (WIPE_ALL | WIPE_GPS) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

#ifdef DEBUG
	fprintf(stderr, "Trying to get timestamp\n");
#endif
	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x07" : (char *)"\x07\x00", 2, TYPE_RATIONAL, endian);
	if (p && datum.type == TYPE_RATIONAL && datum.len == 3)
	{
		unsigned int		*uptr = NULL;
		double					hours, minutes, seconds;

		assert(datum.data_start);
		uptr = (unsigned int *)datum.data_start;

		numerator = *uptr++;
		denominator = *uptr++;

		hours = ((double)numerator / (double)denominator);

		numerator = *uptr++;
		denominator = *uptr++;

		minutes = ((double)numerator / (double)denominator);

		numerator = *uptr++;
		denominator = *uptr++;

		seconds = ((double)numerator / (double)denominator);

		printf("%*s %s%s%02u:%02u:%02u\e[m%s", OUT_WIDTH, "Timestamp:",
				FLAGS & (WIPE_ALL | WIPE_GPS) ? "\e[9;02m" : "",
				DATA_COL,
				(unsigned int)hours,
				(unsigned int)minutes,
				(unsigned int)seconds,
				_EOL);

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

#ifdef DEBUG
	fprintf(stderr, "Trying to get latitude ref\n");
#endif
	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x01" : (char *)"\x01\x00", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII && datum.len == 2)
	{
		char		*q = NULL;

		assert(datum.data_start);
		++count;
		q = (char *)datum.data_start;

		if (*q == 0x4e)
			strcpy(latitude_ref, "N");
		else
		if (*q == 0x53)
			strcpy(latitude_ref, "S");

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

#ifdef DEBUG
	fprintf(stderr, "Trying to get longitude ref\n");
#endif
	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x03" : (char *)"\x03\x00", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII && datum.len == 2)
	{
		char		*q = NULL;

		++count;
		q = (char *)datum.data_start;

		if (*q == 0x45)
			strcpy(longitude_ref, "E");
		else
		if (*q == 0x57)
			strcpy(longitude_ref, "W");

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

#ifdef DEBUG
	fprintf(stderr, "trying to get latitude\n");
#endif
	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x02" : (char *)"\x02\x00", 2, TYPE_RATIONAL, endian);
	if (p && datum.type == TYPE_RATIONAL && datum.len == 3)
	{
		unsigned int		*uptr = NULL;

		uptr = (unsigned int *)datum.data_start;
		
		numerator = *uptr++;
		denominator = *uptr++;

		latitude_deg = ((double)numerator / (double)denominator);

		numerator = *uptr++;
		denominator = *uptr++;

		latitude_min = ((double)numerator / (double)denominator);

		numerator = *uptr++;
		denominator = *uptr++;

		latitude_sec = ((double)numerator / (double)denominator);

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);

		uptr = NULL;
	}

#ifdef DEBUG
	fprintf(stderr, "trying to get longitude\n");
#endif
	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x04" : (char *)"\x04\x00", 2, TYPE_RATIONAL, endian);
	if (p && datum.type == TYPE_RATIONAL && datum.len == 3)
	{
		unsigned int		*uptr = NULL;

		uptr = (unsigned int *)datum.data_start;

		numerator = *uptr++;
		denominator = *uptr++;

		longitude_deg = ((double)numerator / (double)denominator);

		numerator = *uptr++;
		denominator = *uptr++;

		longitude_min = ((double)numerator / (double)denominator);

		numerator = *uptr++;
		denominator = *uptr++;

		longitude_sec = ((double)numerator / (double)denominator);

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);

		uptr = NULL;
	}

#ifdef DEBUG
	fprintf(stderr, "trying to get satellites\n");
#endif
	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x05" : (char *)"\x05\x00", 2, TYPE_ASCII, endian);

	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Satellites:",
				FLAGS & (WIPE_ALL | WIPE_GPS) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

	if (count)
	{
		memset(tmp_buf, 0, 256);
		snprintf(tmp_buf, 256, "%s%08.4lf° %08.4lf' %08.4lf'' %s\e[m",
				DATA_COL,
				latitude_deg, latitude_min, latitude_sec,
				latitude_ref);

		printf("%*s %s%s%s",
				OUT_WIDTH, "Latitude:",
				(FLAGS & (WIPE_ALL | WIPE_GPS)) ? "\e[9;02m" : "", tmp_buf, _EOL);

		memset(tmp_buf, 0, 256);
		snprintf(tmp_buf, 256, "%s%08.4lf° %08.4lf' %08.4lf'' %s\e[m",
				DATA_COL,
				longitude_deg, longitude_min, longitude_sec,
				longitude_ref);

		printf("%*s %s%s%s",
				OUT_WIDTH, "Longitude:",
				(FLAGS & (WIPE_ALL | WIPE_GPS)) ? "\e[9;02m" : "", tmp_buf, _EOL);
	}

	restore_signal_handler();

	return count;
}

int
get_make_model(file_t *file, int endian)
{
	void					*p = NULL;
	int						count;
	datum_t				datum;

	setup_signal_handler();
	count = 0;

	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x0f" : (char *)"\x0f\x01", 2, TYPE_ASCII, endian);

	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Manufacturer:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x10" : (char *)"\x10\x01", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Model:",
					FLAGS & (WIPE_ALL | WIPE_DEVICE) ? "\e[9;02m" : "",
					DATA_COL,
					(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xc6\x14" : (char *)"\x14\xc6", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Unique Camera Model:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xc6\x2f" : (char *)"\x2f\xc6", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Camera Serial:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xc7\xa1" : (char *)"\xa1\xc7", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Camera Label:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xa4\x31" : (char *)"\x31\xa4", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Body Serial:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x31" : (char *)"\x31\x01", 2, TYPE_ASCII, endian);
	if (p)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Software:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x0b" : (char *)"\x0b\x00", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Processing Software:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x3c" : (char *)"\x3c\x01", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Host Computer:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x4d" : (char *)"\x4d\x01", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Ink Names:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x92\x7c" : (char *)"\x7c\x92", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Makernote:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	restore_signal_handler();

	return count;
}

int
get_miscellaneous_data(file_t *file, int endian)
{
	datum_t		datum;
	void			*p = NULL;
	int				count;

	setup_signal_handler();
	count = 0;

	/* Get image description */
	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x0e" : (char *)"\x0e\x01", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Image Description:",
					FLAGS & (WIPE_ALL | WIPE_MISC) ? "\e[9;02m" : "",
					DATA_COL,
					(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_MISC))
			wipe_data(file, &datum);
	}

	/* Get comments */
	p = get_data_offset(file, &datum, endian ? (char *)"\x90\x86" : (char *)"\x86\x90", 2, TYPE_COMMENT, endian);
	if (p && datum.type == TYPE_COMMENT)
	  {
			++count;
			printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Comment:",
						FLAGS & (WIPE_ALL | WIPE_COMMENT) ? "\e[9;02m" : "",
						DATA_COL,
						(char *)datum.data_start, _EOL);
			if (FLAGS & (WIPE_ALL | WIPE_COMMENT))
				wipe_data(file, &datum);
	  }

	clear_struct(&datum);
	p = get_data_offset(file, &datum, endian ? (char *)"\x92\x86" : (char *)"\x86\x92", 2, TYPE_COMMENT, endian);
	if (p && datum.type == TYPE_COMMENT)
	{
		char			*q = NULL;

		q = (char *)datum.data_start;
	
		if (!isalpha(*q) && !isdigit(*q))
		{
			while (!isalpha(*q)
				&& !isdigit(*q)
				&& q < (char *)((char *)datum.data_start + (size_t)datum.len))
				++q;

			if (isalpha(*q) || isdigit(*q))
			{
				++count;
				printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Comment:",
						FLAGS & (WIPE_ALL | WIPE_COMMENT) ? "\e[9;02m" : "",
						DATA_COL,
						q, _EOL);
				if (FLAGS & (WIPE_ALL | WIPE_COMMENT))
					wipe_data(file, &datum);
			}
		}
		else
		{
			++count;
			printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Comment:",
					FLAGS & (WIPE_ALL | WIPE_COMMENT) ? "\e[9;02m" : "",
					DATA_COL,
					q, _EOL);
			if (FLAGS & (WIPE_ALL | WIPE_COMMENT))
				wipe_data(file, &datum);
		}
	}

	/* Get unique image ID */
	p = get_data_offset(file, &datum, endian ? (char *)"\xa4\x20" : (char *)"\x20\xa4", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Unique ID:",
					FLAGS & (WIPE_ALL | WIPE_UID) ? "\e[9;02m" : "",
					DATA_COL,
					(char *)datum.data_start, _EOL);
		if (FLAGS & (WIPE_ALL | WIPE_UID))
				wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x80\x0d" : (char *)"\x0d\x80", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Image ID:",
					FLAGS & (WIPE_ALL | WIPE_MISC) ? "\e[9;02m" : "",
					DATA_COL,
					(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_MISC))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x82\x98" : (char *)"\x98\x82", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Copyright:",
					FLAGS & (WIPE_ALL | WIPE_MISC) ? "\e[9;02m" : "",
					DATA_COL,
					(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_MISC))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xa4\x30" : (char *)"\x30\xa4", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s\e[m%s", OUT_WIDTH, "Camera Owner:",
				FLAGS & (WIPE_ALL | WIPE_MISC) ? "\e[9;02m" : "",
				DATA_COL,
				(char *)datum.data_start, _EOL);

		if (FLAGS & (WIPE_ALL | WIPE_MISC))
			wipe_data(file, &datum);
	}

	restore_signal_handler();

	return count;
}

void *
get_limit(file_t *file)
{
	unsigned char		*p = NULL;
	uint16_t *exif_lenp = NULL;
	uint16_t exif_len;

	exif_len = 0;
	p = (unsigned char *)exif_start(file);
	exif_lenp = (uint16_t *)(p + 2);
	exif_len = ntohs(*exif_lenp);
	if (exif_len > 0x2000)
		exif_len = 0x2000;
	
	return (void *)(p + (size_t)(exif_len));
}
