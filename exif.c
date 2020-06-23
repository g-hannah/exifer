#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <hash_bucket.h>
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

#define UNIX_EPOCH_DATE	"1970:01:01 00:00:00"
#define MILLENIUM_DATE	"2000:01:01 00:00:00"

/*
 * Indices into the exif_flag_t array
 */
enum
{
	TIME_CREATION = 0,
	TIME_ORIGINAL,
	TIME_MODIFIED,
	TIME_DIGITIZED,
	HARDWARE_MODEL,
	HARDWARE_MANUFACTURER,
	IMAGE_COPYRIGHT,
	IMAGE_COMMENT,
	IMAGE_UNIQUE_ID,
	IMAGE_SOFTWARE,
	IMAGE_PROCESSING_SOFTWARE,
	MISC_HOST_COMPUTER,
	MISC_INK_NAMES,
	MISC_MAKERNOTE,
	MISC_IMAGE_DESCRIPTION,
	CAMERA_OWNER,
	CAMERA_SERIAL_NUMBER,
	CAMERA_UNIQUE_CAMERA_MODEL,
	CAMERA_LABEL,
	CAMERA_BODY_SERIAL,
	NR_DATA
};

static exif_flag_t EXIF_FLAGS[NR_DATA] =
{
	{ "Created", "\x90\x04", TYPE_ASCII },
	{ "Original", "\x90\x03", TYPE_ASCII },
	{ "Modified", "\x01\x32", TYPE_ASCII },
	{ "Digitized", "\x90\x02", TYPE_ASCII },
	{ "Camera Model", "\x01\x10", TYPE_ASCII },
	{ "Camera Manufacturer", "\x01\x0f", TYPE_ASCII },
	{ "Image Copyright", "\x82\x98", TYPE_ASCII },
	{ "Image Comment", "\x90\x86", TYPE_COMMENT },
	{ "Image Unique ID", "\xa4\x20", TYPE_ASCII },
	{ "Image Software", "\x01\x31", TYPE_ASCII },
	{ "Image Processing Software", "\x00\x0b", TYPE_ASCII },
	{ "Host Computer", "\x01\x3c", TYPE_ASCII },
	{ "Ink Names", "\x01\x4d", TYPE_ASCII },
	{ "Makernote", "\x92\x7c", TYPE_ASCII },
	{ "Image Description", "\x01\x0e", TYPE_ASCII },
	{ "Camera Owner", "\xa4\x30", TYPE_ASCII },
	{ "Camera Serial Number", "\xc6\x2f", TYPE_ASCII },
	{ "Camera Unique Model", "\xc6\x14", TYPE_ASCII },
	{ "Camera Label", "\xc7\xa1", TYPE_ASCII },
	{ "Camera Body Serial", "\xa4\x31", TYPE_ASCII }
};

enum
{	
	GPS_LATITUDE_LETTER = 0,
	GPS_LONGITUDE_LETTER,
	GPS_VERSION_ID,
	GPS_LATITUDE,
	GPS_LONGITUDE,
	GPS_SATELLITES,
	GPS_NR_DATA
};

static exif_flag_t GPS_FLAGS[GPS_NR_DATA] =
{
	{ "N/S", "\x00\x01", TYPE_ASCII },
	{ "E/W", "\x00\x03", TYPE_ASCII },
	{ "GPS Version ID", "\x00\x00", TYPE_BYTE },
	{ "GPS Latitude", "\x00\x02", TYPE_RATIONAL },
	{ "GPS Longitude", "\x00\x04", TYPE_RATIONAL },
	{ "GPS Satellites", "\x00\x05", TYPE_ASCII }
};

#define DATA_COL	"\x1b[38;5;88m"
#define STRIKE_THROUGH	"\x1b[9;02m"
#define END_COL		"\x1b[m"

static struct sigaction new_act, old_act;
static sigjmp_buf __sigsegv__;

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
	int fd;
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
	return;
}

#define METADATA_LENGTH 12
/**
 * Zero out the exif data and the meta-data that points
 * to where this data is within the file.
 * We have the tag (2 bytes), followed by the type (2 bytes),
 * the length (4 bytes), and the offset (4 bytes).
 */
static void
zero_data(file_t *file, datum_t *datum)
{
	assert(file);
	assert(datum);

	if (mprotect(file->map, file->size, PROT_READ|PROT_WRITE) < 0)
	{
		perror("wipe_data: failed to set file map to PROT_READ|PROT_WRITE\n");
		return;
	}

	memset(datum->tag_p, 0, METADATA_LENGTH);
	memset(datum->data_start, 0, (char *)datum->data_end - (char *)datum->data_start);

	if (mprotect(file->map, file->size, PROT_READ) < 0)
		perror("zero_data: error switching off read/write permissions for mapped file contents\n");

	return;
}

static void *
exif_start(file_t *file)
{
	unsigned char *p = NULL;
	unsigned char *end = NULL;

	assert(file);
	assert(file->map);
	p = (unsigned char *)file->map;
	end = (unsigned char *)file->map_end;

	while (memcmp((char *)APP1_MARKER, (char *)p, 2) && p < end)
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

	for(;;)
	{
		while (memcmp(t, p, 2) && p < (unsigned char *)lim)
			++p;

		if (p == (unsigned char *)lim)
			return NULL;

		uint16_t _type = *((uint16_t *)(p + 2));

		if (endian)
			_type = ntohs(_type);

		if (_type != type)
		{
			p += 2;
			continue;
		}
		else
			break;
	}

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

/**
 * The compiler will complain about this being defined but unused
 * if we are on a little endian machine since the preprocessor
 * will not make use of this function (see get_tag() func), so
 * use the unused attribute.
 */
static uint32_t
__attribute__((unused)) __reverse_bytes32(uint32_t val)
{
	uint8_t t;
	uint8_t *p = (uint8_t *)&val;

	t = p[3];
	p[3] = p[0];
	p[0] = t;

	t = p[2];
	p[2] = p[1];
	p[1] = t;

	return *((uint32_t *)p);
}

static char __tag[2];

/**
 * Tags have been encoded in big endian format.
 *
 * On big endian machines, both ntohs() and htons()
 * won't flip the bytes. We therefore need to manually
 * flip them if we are big endian.
 */
static char *get_tag(char *t, int e)
{
	assert(t);

	uint16_t val;

	val = *((uint16_t *)t);
	if (!e)
	{
#if __BYTE_ORDER == __BIG_ENDIAN
		val = __reverse_bytes32(val);
#else
		val = ntohs(val);
#endif
		memcpy(__tag, &val, 2);
	}
	else
		memcpy(__tag, &val, 2);

	return __tag;
}

/**
 * Parse two uint32_t numbers representing
 * the numerator and denominator and calculate
 * their division, and increment *P by
 * 8 bytes.
 */
double
parse_rational(void **p)
{
	assert(p);

	uint32_t *ptr = *(uint32_t **)p;
	uint32_t n, d;

	assert(ptr);

	n = *ptr++;
	d = *ptr;

	*((uint32_t **)p) += 2;

	if (0 == d)
		return -1.0;

	return (double)n/(double)d;
}

double *
parse_gps_values(void *p)
{
	assert(p);

	double deg, am, as;

	deg = parse_rational(&p);
	if (-1.0 == deg)
		goto fail;

	am = parse_rational(&p);
	if (-1.0 == am)
		goto fail;

	as = parse_rational(&p);
	if (-1.0 == as)
		goto fail;

	double *ret = calloc(3, sizeof(double));
	assert(ret);

	ret[0] = deg;
	ret[1] = am;
	ret[2] = as;

	return ret;

fail:
	return NULL;	
}

/**
 * Extract the exif data corresponding to the
 * flags in EXIF_FLAGS. GPS data needs to be
 * treated specially and cannot be done in the
 * for-loop.
 *
 * @param file Structure with pointer to mapped file contents
 * @param endian Non-zero means the exif-data is big-endian
 */
int
extract_data(file_t *file, int endian)
{
	int i;
	datum_t datum;
	void *p = NULL;
	exif_flag_t *flag = NULL;
	char *tag;

	assert(file);

	for (i = 0; i < NR_DATA; ++i)
	{
		clear_struct(&datum);

		flag = &EXIF_FLAGS[i];

	/*
	 * Gets the tag in the correct endianness.
	 */
		tag = get_tag(flag->flag, endian);
		p = get_data_offset(file, &datum, tag, 2, flag->type, endian);

		if (!p || datum.type != flag->type || !datum.len)
			continue;

#define STRIKETHROUGH	"\e[3;09m"
#define END		"\e[m"
		fprintf(stdout, "%*s: %s%s%s\n",
			(int)NAME_WIDTH, flag->name,
			FLAGS & WIPE_ALL ? STRIKETHROUGH : "",
			(char *)datum.data_start,
			FLAGS & WIPE_ALL ? END : "");

		if (FLAGS & WIPE_ALL)
			zero_data(file, &datum);
	}

	char lat_NS[2];
	char long_EW[2];

	flag = &GPS_FLAGS[GPS_LATITUDE_LETTER];
	tag = get_tag(flag->flag, endian);
	clear_struct(&datum);
	p = get_data_offset(file, &datum, tag, 2, flag->type, endian);

/*
 * Assume that failure to find a piece of GPS data means no GPS data encoded.
 */
	if (!p || datum.type != flag->type)
		goto end;

	memcpy(lat_NS, datum.data_start, 1);
	lat_NS[1] = 0;

	flag = &GPS_FLAGS[GPS_LONGITUDE_LETTER];
	tag = get_tag(flag->flag, endian);
	clear_struct(&datum);
	p = get_data_offset(file, &datum, tag, 2, flag->type, endian);

	if (!p || datum.type != flag->type)
		goto end;

	memcpy(long_EW, datum.data_start, 1);
	long_EW[1] = 0;

	flag = &GPS_FLAGS[GPS_LATITUDE];
	tag = get_tag(flag->flag, endian);
	clear_struct(&datum);
	p = get_data_offset(file, &datum, tag, 2, flag->type, endian);

	if (!p || datum.type != flag->type)
		goto end;

	double *vals = NULL;
	double latd, latam, latas;
	double lngd, lngam, lngas;

	vals = parse_gps_values(datum.data_start);
	if (!vals)
		goto end;

	latd = vals[0];
	latam = vals[1];
	latas = vals[2];

	free(vals);

	flag = &GPS_FLAGS[GPS_LONGITUDE];
	tag = get_tag(flag->flag, endian);
	clear_struct(&datum);
	p = get_data_offset(file, &datum, tag, 2, flag->type, endian);
	if (!p || datum.type != flag->type)
		goto end;

	vals = parse_gps_values(datum.data_start);
	if (!vals)
		goto end;

	lngd = vals[0];
	lngam = vals[1];
	lngas = vals[2];

	free(vals);

	fprintf(stderr,
		"%*s: %sLat %.2lf°%.2lf'%.2lf″ %s, Long %.2lf°%.2lf'%.2lf″ %s%s\n",
		(int)NAME_WIDTH, "Location",
		FLAGS & WIPE_ALL ? STRIKETHROUGH : "",
		latd, latam, latas, lat_NS, lngd, lngam, lngas, long_EW,
		FLAGS & WIPE_ALL ? END : "");

	if (FLAGS & WIPE_ALL)
		zero_data(file, &datum);

end:
	return 0;
}

int
get_date_time(file_t *file, int endian)
{
	int count;
	datum_t datum;
	void *p = NULL;

	setup_signal_handler();
	count = 0;

	p = get_data_offset(file, &datum, endian ? (char *)"\x90\x02" : (char *)"\x02\x90", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Digitised:",
					FLAGS & (WIPE_ALL | WIPE_DATE) ? STRIKE_THROUGH : "",
					(char *)datum.data_start, _EOL,
					FLAGS & (WIPE_ALL | WIPE_DATE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DATE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x90\x03" : (char *)"\x03\x90", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Original:",
				FLAGS & (WIPE_ALL | WIPE_DATE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DATE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DATE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x90\x04" : (char *)"\x04\x90", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Created:",
				FLAGS & (WIPE_ALL | WIPE_DATE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DATE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DATE))
				wipe_data(file, &datum);
	}
	 
	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x32" : (char *)"\x32\x01", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Modified:",
				FLAGS & (WIPE_ALL | WIPE_DATE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DATE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DATE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xc7\x1b" : (char *)"\x1b\xc7", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Preview:",
				FLAGS & (WIPE_ALL | WIPE_DATE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DATE) ? END_COL : "");

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

	datum_t datum;
	void *p = NULL;
	int count;
	double latitude_deg;
	double latitude_min;
	double latitude_sec;
	double longitude_deg;
	double longitude_min;
	double longitude_sec;
	static char latitude_ref[16];
	static char longitude_ref[16];
	static char tmp_buf[256];
	unsigned int numerator;
	unsigned int denominator;

	setup_signal_handler();
	count = 0;

	p = get_data_offset(file, &datum, (char *)"\x00\x00", 2, TYPE_BYTE, endian);
	if (p && datum.type == TYPE_BYTE && datum.len == 4)
	{
		++count;

		char *ptr = NULL;
		char *tptr = NULL;
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
		
		printf("%*s %s%s%s%s", OUT_WIDTH, "Version ID:",
				FLAGS & (WIPE_ALL | WIPE_GPS) ? STRIKE_THROUGH : "",
				tmp_buf, _EOL,
				FLAGS & (WIPE_ALL | WIPE_GPS) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x1d" : (char *)"\x1d\x00", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		assert(datum.data_start);
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Datestamp:",
				FLAGS & (WIPE_ALL | WIPE_GPS) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_GPS) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x07" : (char *)"\x07\x00", 2, TYPE_RATIONAL, endian);
	if (p && datum.type == TYPE_RATIONAL && datum.len == 3)
	{
		unsigned int *uptr = NULL;
		double hours, minutes, seconds;

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

		printf("%*s %s%02u:%02u:%02u%s%s", OUT_WIDTH, "Timestamp:",
				FLAGS & (WIPE_ALL | WIPE_GPS) ? STRIKE_THROUGH : "",
				(unsigned int)hours,
				(unsigned int)minutes,
				(unsigned int)seconds,
				_EOL,
				FLAGS & (WIPE_ALL | WIPE_GPS) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x01" : (char *)"\x01\x00", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII && datum.len == 2)
	{
		char		*q = NULL;

		assert(datum.data_start);
		++count;

		q = (char *)datum.data_start;

		memset(latitude_ref, 0, 16);

		if (*q == 0x4e)
			strcpy(latitude_ref, "N");
		else
		if (*q == 0x53)
			strcpy(latitude_ref, "S");

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x03" : (char *)"\x03\x00", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII && datum.len == 2)
	{
		char		*q = NULL;

		assert(datum.data_start);
		++count;

		q = (char *)datum.data_start;

		memset(longitude_ref, 0, 16);

		if (*q == 0x45)
			strcpy(longitude_ref, "E");
		else
		if (*q == 0x57)
			strcpy(longitude_ref, "W");

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

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

	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x05" : (char *)"\x05\x00", 2, TYPE_ASCII, endian);

	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Satellites:",
				FLAGS & (WIPE_ALL | WIPE_GPS) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_GPS) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_GPS))
			wipe_data(file, &datum);
	}

	if (count)
	{
		memset(tmp_buf, 0, 256);

		snprintf(tmp_buf, 256, "%08.4lf° %08.4lf' %08.4lf'' %s%s",
				latitude_deg, latitude_min, latitude_sec,
				latitude_ref,
				FLAGS & (WIPE_ALL | WIPE_DATE) ? END_COL : "");

		printf("%*s %s%s%s",
				OUT_WIDTH, "Latitude:",
				(FLAGS & (WIPE_ALL | WIPE_GPS)) ? STRIKE_THROUGH : "", tmp_buf, _EOL);

		memset(tmp_buf, 0, 256);

		snprintf(tmp_buf, 256, "%08.4lf° %08.4lf' %08.4lf'' %s%s",
				longitude_deg, longitude_min, longitude_sec,
				longitude_ref,
				FLAGS & (WIPE_ALL | WIPE_DATE) ? END_COL : "");

		printf("%*s %s%s%s",
				OUT_WIDTH, "Longitude:",
				(FLAGS & (WIPE_ALL | WIPE_GPS)) ? STRIKE_THROUGH : "", tmp_buf, _EOL);
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
		printf("%*s %s%s%s%s", OUT_WIDTH, "Manufacturer:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x10" : (char *)"\x10\x01", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Model:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xc6\x14" : (char *)"\x14\xc6", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Unique Camera Model:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xc6\x2f" : (char *)"\x2f\xc6", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Camera Serial:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xc7\xa1" : (char *)"\xa1\xc7", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Camera Label:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xa4\x31" : (char *)"\x31\xa4", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Body Serial:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x31" : (char *)"\x31\x01", 2, TYPE_ASCII, endian);
	if (p)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Software:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x00\x0b" : (char *)"\x0b\x00", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Processing Software:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x3c" : (char *)"\x3c\x01", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Host Computer:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x01\x4d" : (char *)"\x4d\x01", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Ink Names:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_DEVICE))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x92\x7c" : (char *)"\x7c\x92", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Makernote:",
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_DEVICE) ? END_COL : "");

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
		printf("%*s %s%s%s%s", OUT_WIDTH, "Image Description:",
				FLAGS & (WIPE_ALL | WIPE_MISC) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_MISC) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_MISC))
			wipe_data(file, &datum);
	}

	/* Get comments */
	p = get_data_offset(file, &datum, endian ? (char *)"\x90\x86" : (char *)"\x86\x90", 2, TYPE_COMMENT, endian);
	if (p && datum.type == TYPE_COMMENT)
	  {
			++count;
			printf("%*s %s%s%s%s", OUT_WIDTH, "Comment:",
					FLAGS & (WIPE_ALL | WIPE_COMMENT) ? STRIKE_THROUGH : "",
					(char *)datum.data_start, _EOL,
					FLAGS & (WIPE_ALL | WIPE_COMMENT) ? END_COL : "");

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
				printf("%*s %s%s%s%s", OUT_WIDTH, "Comment:",
						FLAGS & (WIPE_ALL | WIPE_COMMENT) ? STRIKE_THROUGH : "",
						q, _EOL,
						FLAGS & (WIPE_ALL | WIPE_COMMENT) ? END_COL : "");

				if (FLAGS & (WIPE_ALL | WIPE_COMMENT))
					wipe_data(file, &datum);
			}
		}
		else
		{
			++count;
			printf("%*s %s%s%s%s", OUT_WIDTH, "Comment:",
					FLAGS & (WIPE_ALL | WIPE_COMMENT) ? STRIKE_THROUGH : "",
					q, _EOL,
					FLAGS & (WIPE_ALL | WIPE_COMMENT) ? END_COL : "");

			if (FLAGS & (WIPE_ALL | WIPE_COMMENT))
				wipe_data(file, &datum);
		}
	}

	/* Get unique image ID */
	p = get_data_offset(file, &datum, endian ? (char *)"\xa4\x20" : (char *)"\x20\xa4", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Unique ID:",
				FLAGS & (WIPE_ALL | WIPE_UID) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_UID) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_UID))
				wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x80\x0d" : (char *)"\x0d\x80", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Image ID:",
				FLAGS & (WIPE_ALL | WIPE_MISC) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_MISC) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_MISC))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\x82\x98" : (char *)"\x98\x82", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Copyright:",
				FLAGS & (WIPE_ALL | WIPE_MISC) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_MISC) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_MISC))
			wipe_data(file, &datum);
	}

	p = get_data_offset(file, &datum, endian ? (char *)"\xa4\x30" : (char *)"\x30\xa4", 2, TYPE_ASCII, endian);
	if (p && datum.type == TYPE_ASCII)
	{
		++count;
		printf("%*s %s%s%s%s", OUT_WIDTH, "Camera Owner:",
				FLAGS & (WIPE_ALL | WIPE_MISC) ? STRIKE_THROUGH : "",
				(char *)datum.data_start, _EOL,
				FLAGS & (WIPE_ALL | WIPE_MISC) ? END_COL : "");

		if (FLAGS & (WIPE_ALL | WIPE_MISC))
			wipe_data(file, &datum);
	}

	restore_signal_handler();

	return count;
}

void *
get_limit(file_t *file)
{
	unsigned char *p = NULL;
	//uint16_t exif_len;

	p = (unsigned char *)exif_start(file);
	return (void *)((char *)p + 0x1000);
/*
	exif_len = 0;
	p = (unsigned char *)exif_start(file);
	exif_len = ntohs(*((uint16_t *)(p + 2)));

	if (exif_len > 0x2000)
		exif_len = 0x2000;
	
	return (void *)(p + (size_t)(exif_len));
*/
}
