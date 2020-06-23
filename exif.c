#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "exif.h"
#include "logging.h"

#define __unused __attribute__((unused))

#define UNIX_EPOCH_DATE	"1970:01:01 00:00:00"
#define MILLENIUM_DATE	"2000:01:01 00:00:00"

#define WRITEABLE(f) mprotect((f)->map, (f)->size, PROT_READ|PROT_WRITE)
#define READABLE(f) mprotect((f)->map, (f)->size, PROT_READ)

int count = 0;

typedef struct Data_Array
{
	datum_t *data;
	int nr;
} data_array_t;

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
	NR_SENSITIVE
};

static exif_flag_t SENSITIVE_DATA[NR_SENSITIVE] =
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

/*
 * Part of sensitive data but has to be
 * extracted separately from the rest
 * due to how it is parsed.
 */
enum
{	
	GPS_LATITUDE_LETTER = 0,
	GPS_LONGITUDE_LETTER,
	GPS_VERSION_ID,
	GPS_DATESTAMP,
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
	{ "GPS Datestamp", "\x00\x1d", TYPE_ASCII },
	{ "GPS Latitude", "\x00\x02", TYPE_RATIONAL },
	{ "GPS Longitude", "\x00\x04", TYPE_RATIONAL },
	{ "GPS Satellites", "\x00\x05", TYPE_ASCII }
};

#define DATA_COL	"\x1b[38;5;88m"
#define STRIKE_THROUGH	"\x1b[9;02m"
#define END_COL		"\x1b[m"

static void
__attribute__((constructor)) __Exifer_Init(void)
{
	srand(time(NULL));
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

/*
 * The compiler may complain about these reverse functions since
 * they may not be included in the code by the preprocessor
 * depending on the endianness of the machine. So used attribute
 * unused.
 */
static uint32_t
__unused __reverse_bytes32(uint32_t val)
{
	char *p = (char *)&val;
	char t;

	t = p[3];
	p[3] = p[0];
	p[0] = t;

	t = p[2];
	p[2] = p[1];
	p[1] = t;

	return *((uint32_t *)p);
}

static uint32_t
__unused __reverse_bytes16(uint16_t val)
{
	uint8_t t;
	uint8_t *p = (uint8_t *)&val;

	t = p[1];
	p[1] = p[0];
	p[0] = t;

	return *((uint16_t *)p);
}

/**
 * Return the value in the correct endianness
 * for the machine we are running on.
 *
 * @param val This is the value we extracted from the exif data
 * @param endian This is the endianness the exif data is encoded in
 */
static uint16_t
G16BIT_VAL(uint16_t val, int endian)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	if (endian)
	{
		return ntohs(val);
	}
	else
		return val;
#elif __BYTE_ORDER == __BIG_ENDIAN
	if (0 == endian)
	{
		return __reverse_bytes16(val);
	}
	else
		return val;
#else
# error "What kind of machine is this...?"
#endif
}

static uint32_t
G32BIT_VAL(uint32_t val, int endian)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	if (endian)
		return ntohl(val);
	else
		return val;
#elif __BYTE_ORDER == __BIG_ENDIAN
	if (0 == endian)
		return __reverse_bytes32(val);
	else
		return val;
#else
# error "What kind of machine is this...?"
#endif
}

static void *
get_data(file_t *file, datum_t *dptr, char *str, size_t slen, uint16_t type, int endian)
{
	unsigned char *p = NULL;

	assert(file);
	assert(dptr);
	assert(str);
	assert(lim > file->map); // LIM is global var
	assert(file->new_end <= file->map_end);

	p = (unsigned char *)exif_start(file);

	clear_struct(dptr);

	char c1 = str[0];
	unsigned char *e = (unsigned char *)lim;

	while (1)
	{
		p = memchr(p, c1, e - p);
		if (!p)
			return NULL;

		if (memcmp(p, str, slen))
		{
			++p;
			continue;
		}

		if (p == e)
			return NULL;

		uint16_t _type = G16BIT_VAL(*((uint16_t *)(p + 2)), endian);

		if (_type != type)
		{
			++p;
			continue;
		}

		break;
	}

/*
 * Save pointers to the metadata within the file so that if the user
 * has specified to wipe the data, we can also wipe this metadata.
 */
	dptr->tag_p = (void *)p;
	dptr->type_p = (void *)((unsigned char *)p + 2);
	dptr->len_p = (void *)((unsigned char *)p + 4);
	dptr->offset_p = (void *)((unsigned char *)p + 8);

/*
 * Get the values in the correct endianness.
 */
	dptr->type = G16BIT_VAL(*((uint16_t *)dptr->type_p), endian);
	dptr->len = G32BIT_VAL(*((uint32_t *)dptr->len_p), endian);
	dptr->offset = G32BIT_VAL(*((uint32_t *)dptr->offset_p), endian);

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

		if (dptr->data_end >= file->map_end)
			return NULL;

		p = NULL;
		return (void *)dptr;
	}
}

static char __tag[2];

/**
 * We don't use the GXXBIT_VAL() functions here because
 * regardless of which processor we are running on, the
 * exif tags have been hardcoded in big endian. We just
 * need to flip the tag around if the exif data itself
 * is encoded in little endian.
 */
static char *get_tag(char *t, int e)
{
	assert(t);

	uint16_t val;

	val = *((uint16_t *)t);
	if (!e)
	{
/*
 * If the processor is big endian, we need to use our own
 * reversing function since both ntohs/htons will do nothing.
 */
#if __BYTE_ORDER == __BIG_ENDIAN
		val = __reverse_bytes16(val);
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

static data_array_t *new_data_array(void) __unused;

static data_array_t *
new_data_array(void)
{
	data_array_t *arr = malloc(sizeof(data_array_t));

	if (NULL == arr)
		return NULL;

	memset(arr, 0, sizeof(*arr));
	return arr;
}

/**
 * Extend the datum_t array in ARR and memcpy
 * data in D. Do not free D as it is a stack
 * address passed from the caller.
 */
static void
__unused add_datum(data_array_t *arr, datum_t *d)
{
	assert(arr);
	assert(d);

	if (NULL == arr->data)
		arr->data = calloc(1, sizeof(datum_t));
	else
		arr->data = realloc(arr->data, (arr->nr+1) * sizeof(datum_t));

	assert(arr->data);

	memcpy(&arr->data[arr->nr], d, sizeof(datum_t));
	++arr->nr;

	return;
}

//static data_array_t *sensitive = NULL;

int
extract_sensitive(file_t *file, int endian)
{
	assert(file);

	int i;
	datum_t datum;
	void *p = NULL;
	exif_flag_t *flag = NULL;
	char *tag;

	//sensitive = new_data_array();
	//assert(sensitive);

	for (i = 0; i < NR_SENSITIVE; ++i)
	{
		clear_struct(&datum);

		flag = &SENSITIVE_DATA[i];
	/*
	 * Gets the tag in the correct endianness.
	 */
		tag = get_tag(flag->flag, endian);
		p = get_data(file, &datum, tag, 2, flag->type, endian);

		//add_datum(sensitive, &datum);

		if (!p || datum.type != flag->type || !datum.len)
			continue;

#define STRIKETHROUGH	"\e[3;09m"
#define END		"\e[m"
		fprintf(stdout, "%*s: %s%s%s\n",
			(int)NAME_WIDTH, flag->name,
			FLAGS & WIPE_SENSITIVE ? STRIKETHROUGH : "",
			(char *)datum.data_start,
			FLAGS & WIPE_SENSITIVE ? END : "");

		if (FLAGS & WIPE_SENSITIVE)
			zero_data(file, &datum);

		++count;
	}

/*
 * Get the GPS Version ID data.
 */
	flag = &GPS_FLAGS[GPS_VERSION_ID];
	tag = get_tag(flag->flag, endian);

	p = get_data(file, &datum, tag, 2, flag->type, endian);
	if (p && datum.type == flag->type && datum.len > 0)
	{
		char *ptr = (char *)datum.data_start;
		char *t;
		char *e = ptr + 4;
		static char version_id[64];
		int bad = 0;

		t = version_id;

		while (ptr < e)
		{
			*t++ = (*ptr++ + '0');
			*t++ = '.';

			if (*(t-2) < '0' || *(t-2) > '9')
				++bad;
		}

		*--t = 0;

		if (!bad)
		{
			fprintf(stdout, "%*s: %s%s%s\n",
				(int)NAME_WIDTH, flag->name,
				FLAGS & WIPE_SENSITIVE ? STRIKETHROUGH : "",
				version_id,
				FLAGS & WIPE_SENSITIVE ? END : "");

			if (FLAGS & WIPE_SENSITIVE)
				zero_data(file, &datum);

			++count;
		}
	}

/*
 * Get the GPS Datestamp data.
 */
	flag = &GPS_FLAGS[GPS_DATESTAMP];
	tag = get_tag(flag->flag, endian);

	p = get_data(file, &datum, tag, 2, flag->type, endian);
	if (p && datum.type == flag->type && datum.len > 0)
	{
		fprintf(stdout, "%*s: %s%s%s\n",
			(int)NAME_WIDTH, flag->name,
			FLAGS & WIPE_SENSITIVE ? STRIKETHROUGH : "",
			(char *)datum.data_start,
			FLAGS & WIPE_SENSITIVE ? END : "");

		if (FLAGS & WIPE_SENSITIVE)
			zero_data(file, &datum);

		++count;
	}

/*
 * Extract the actual GPS data, including the letters indicating
 * whether latitude is North or South and longitude East or West.
 *
 * Location data is coded as 3 RATIONAL types for degrees,
 * arc-minutes and arc-seconds. A RATIONAL type is two uint32_t
 * values, first being the numerator and the second the denominator:
 *
 *     degrees        arc-minutes     arc-seconds
 * [ num ][ denom ][ num ][ denom ][ num ][ denom ]
 *
 * for a total of 24 bytes of data.
 */
	char lat_NS[2];
	char long_EW[2];
	//datum_t latNS, lngEW, dlat, dlng;

	flag = &GPS_FLAGS[GPS_LATITUDE_LETTER];
	tag = get_tag(flag->flag, endian);

	p = get_data(file, &datum, tag, 2, flag->type, endian);

/*
 * Assume that failure to find a piece of GPS data means no GPS data encoded.
 */
	if (!p || datum.type != flag->type)
		goto end;

	memcpy(lat_NS, datum.data_start, 1);
	lat_NS[1] = 0;

	flag = &GPS_FLAGS[GPS_LONGITUDE_LETTER];
	tag = get_tag(flag->flag, endian);

	p = get_data(file, &datum, tag, 2, flag->type, endian);

	if (!p || datum.type != flag->type)
		goto end;

	memcpy(long_EW, datum.data_start, 1);
	long_EW[1] = 0;

	flag = &GPS_FLAGS[GPS_LATITUDE];
	tag = get_tag(flag->flag, endian);

	p = get_data(file, &datum, tag, 2, flag->type, endian);

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

	p = get_data(file, &datum, tag, 2, flag->type, endian);
	if (!p || datum.type != flag->type)
		goto end;

	vals = parse_gps_values(datum.data_start);
	if (!vals)
		goto end;

	lngd = vals[0];
	lngam = vals[1];
	lngas = vals[2];

	free(vals);

	//add_datum(sensitive, &latNS);
	//add_datum(sensitive, &lngEW);
	//add_datum(sensitive, &dlat);
	//add_datum(sensitive, &dlng);

	count += 4;

	fprintf(stderr,
		"%*s: %sLat %.2lf°%.2lf'%.2lf″ %s, Long %.2lf°%.2lf'%.2lf″ %s%s\n",
		(int)NAME_WIDTH, "Location",
		FLAGS & WIPE_SENSITIVE ? STRIKETHROUGH : "",
		latd, latam, latas, lat_NS, lngd, lngam, lngas, long_EW,
		FLAGS & WIPE_SENSITIVE ? END : "");

	if (FLAGS & WIPE_SENSITIVE)
		zero_data(file, &datum);
end:
	return count;
}

static void
__unused show_sensitive(data_array_t *arr)
{
	assert(arr);

	int i;
	int nr = arr->nr;
	datum_t *d = NULL;
	void *ptr;
	double dbl;

	for (i = 0; i < nr; ++i)
	{
		d = &arr->data[i];

		switch(d->type)
		{
			case TYPE_ASCII:
			case TYPE_BYTE:
			case TYPE_COMMENT:

				fprintf(stdout, "%s\n", (char *)d->data_start);

				break;

			case TYPE_RATIONAL:

				ptr = d->data_start;
				while (ptr < d->data_end)
				{
					dbl = parse_rational(&ptr);
					fprintf(stdout, "%.2lf ", dbl);
				}

				fprintf(stdout, "\n");

				break;

			default:
				break;
		}
	}
}

static void
__unused free_data_array(data_array_t *arr)
{
	assert(arr);

	if (NULL == arr->data)
		return;

	free(arr->data);
	free(arr);

	return;
}

static void
__unused wipe_sensitive(file_t *file, data_array_t *arr)
{
	assert(file);
	assert(arr);

	int i;
	int nr = arr->nr;
	datum_t *d;

	for (i = 0; i < nr; ++i)
	{
		d = &arr->data[i];
		zero_data(file, d);
	}

	return;
}

static data_array_t *
get_date_data(file_t *file, int endian)
{
	assert(file);

	exif_flag_t *flag;
	char *tag;
	void *p;
	datum_t datum;

	data_array_t *arr = new_data_array();
	assert(arr);

	flag = &SENSITIVE_DATA[TIME_CREATION];
	tag = get_tag(flag->flag, endian);
	p = get_data(file, &datum, tag, 2, flag->type, endian);

	if (p && datum.type == flag->type && datum.len > 0)
		add_datum(arr, &datum);

	flag = &SENSITIVE_DATA[TIME_ORIGINAL];
	tag = get_tag(flag->flag, endian);
	p = get_data(file, &datum, tag, 2, flag->type, endian);

	if (p && datum.type == flag->type && datum.len > 0)
		add_datum(arr, &datum);

	flag = &SENSITIVE_DATA[TIME_MODIFIED];
	tag = get_tag(flag->flag, endian);
	p = get_data(file, &datum, tag, 2, flag->type, endian);

	if (p && datum.type == flag->type && datum.len > 0)
		add_datum(arr, &datum);

	flag = &SENSITIVE_DATA[TIME_DIGITIZED];
	tag = get_tag(flag->flag, endian);
	p = get_data(file, &datum, tag, 2, flag->type, endian);

	if (p && datum.type == flag->type && datum.len > 0)
		add_datum(arr, &datum);

	return arr;
}

static void
replace_dates_with_fake(data_array_t *dates)
{
	assert(dates);

	int i;
	int nr = dates->nr;
	datum_t *d;
	time_t now = time(NULL);
	struct tm *tm = NULL;

	now -= (rand()%now);
	tm = gmtime(&now);

	static char stime[256];
	strftime(stime, 256, "%Y:%m:%d %H:%M:%S", tm);

	for (i = 0; i < nr; ++i)
	{
		d = &dates->data[i];
		strcpy((char *)d->data_start, stime);
	}

	fprintf(stderr, "Replaced dates in exif data with random date %s\n", stime);

	return;
}

/**
 * @param file Structure with pointer to mapped file contents
 * @param endian Non-zero means the exif-data is big-endian
 */
int
extract_data(file_t *file, int endian)
{
	assert(file);

	int c;

	if (FLAGS & FL_FAKE_DATES)
	{
		data_array_t *dates = get_date_data(file, endian);
		assert(dates);

		WRITEABLE(file);
		replace_dates_with_fake(dates);
		READABLE(file);

		c = dates->nr;

		free_data_array(dates);
	}
	else
	{
		c = extract_sensitive(file, endian);
	}

	return c;
	//show_sensitive(sensitive);

	//if (FLAGS & WIPE_SENSITIVE)
	//	wipe_sensitive(file, sensitive);

	//free_data_array(sensitive);
}

#if 0
int
get_date_time(file_t *file, int endian)
{
	int count;
	datum_t datum;
	void *p = NULL;

	setup_signal_handler();
	count = 0;

	p = get_data(file, &datum, endian ? (char *)"\x90\x02" : (char *)"\x02\x90", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x90\x03" : (char *)"\x03\x90", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x90\x04" : (char *)"\x04\x90", 2, TYPE_ASCII, endian);
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
	 
	p = get_data(file, &datum, endian ? (char *)"\x01\x32" : (char *)"\x32\x01", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\xc7\x1b" : (char *)"\x1b\xc7", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, (char *)"\x00\x00", 2, TYPE_BYTE, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x00\x1d" : (char *)"\x1d\x00", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x00\x07" : (char *)"\x07\x00", 2, TYPE_RATIONAL, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x00\x01" : (char *)"\x01\x00", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x00\x03" : (char *)"\x03\x00", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x00\x02" : (char *)"\x02\x00", 2, TYPE_RATIONAL, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x00\x04" : (char *)"\x04\x00", 2, TYPE_RATIONAL, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x00\x05" : (char *)"\x05\x00", 2, TYPE_ASCII, endian);

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

	p = get_data(file, &datum, endian ? (char *)"\x01\x0f" : (char *)"\x0f\x01", 2, TYPE_ASCII, endian);

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

	p = get_data(file, &datum, endian ? (char *)"\x01\x10" : (char *)"\x10\x01", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\xc6\x14" : (char *)"\x14\xc6", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\xc6\x2f" : (char *)"\x2f\xc6", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\xc7\xa1" : (char *)"\xa1\xc7", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\xa4\x31" : (char *)"\x31\xa4", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x01\x31" : (char *)"\x31\x01", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x00\x0b" : (char *)"\x0b\x00", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x01\x3c" : (char *)"\x3c\x01", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x01\x4d" : (char *)"\x4d\x01", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x92\x7c" : (char *)"\x7c\x92", 2, TYPE_ASCII, endian);
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
	p = get_data(file, &datum, endian ? (char *)"\x01\x0e" : (char *)"\x0e\x01", 2, TYPE_ASCII, endian);
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
	p = get_data(file, &datum, endian ? (char *)"\x90\x86" : (char *)"\x86\x90", 2, TYPE_COMMENT, endian);
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
	p = get_data(file, &datum, endian ? (char *)"\x92\x86" : (char *)"\x86\x92", 2, TYPE_COMMENT, endian);
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
	p = get_data(file, &datum, endian ? (char *)"\xa4\x20" : (char *)"\x20\xa4", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x80\x0d" : (char *)"\x0d\x80", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\x82\x98" : (char *)"\x98\x82", 2, TYPE_ASCII, endian);
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

	p = get_data(file, &datum, endian ? (char *)"\xa4\x30" : (char *)"\x30\xa4", 2, TYPE_ASCII, endian);
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
#endif

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
