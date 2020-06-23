#ifndef _EXIF_H
#define _EXIF_H	1

#include <stdint.h>

int count;

#define _EOL "\n"
#define NAME_WIDTH 25

#define BUILD	"0.3.0"

#define clear_struct(s) memset((s), 0, sizeof(*(s)))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define APP1_MARKER	"\xff\xe1"
#define END_MARKER	"\xff\xd8"
#define SECTION_COL	"\e[38;5;31m"
#define INFO_COL	"  \e[3;01m\e[38;5;125m"

#define TYPE_BYTE	0x0001
#define TYPE_ASCII	0x0002
#define TYPE_SHORT	0x0003
#define TYPE_RATIONAL	0x0005
#define TYPE_COMMENT	0x0007
#define TYPE_SRATIONAL	0x000a

#define OUT_WIDTH	20
#define MAX_PATH_LEN	1024

typedef struct Exif_Flag
{
	char *name;
	char *flag;
	uint16_t type;
} exif_flag_t;

typedef struct datum_t
{
	void *tag_p;
	void *type_p;
	void *len_p;
	void *offset_p;
	unsigned short type;
	unsigned int len;
	unsigned int offset;
	void *data_start;
	void *data_end;
} datum_t;

typedef struct file_t
{
	char fullpath[MAX_PATH_LEN];
	size_t size;
	int fd;
	void *map;
	void *map_end;
	void *new_end;
} file_t;

#define WIPE_SENSITIVE	0x00000001u
#define FL_FAKE_DATES	0x00000002u

typedef struct Options Options;

int get_date_time(file_t *, int) __nonnull ((1)) __wur;
int get_gps_data(file_t *, int) __nonnull ((1)) __wur;
int get_make_model(file_t *, int) __nonnull ((1)) __wur;
int get_miscellaneous_data(file_t *, int) __nonnull ((1)) __wur;
int get_test(file_t *, int) __nonnull ((1)) __wur;

int extract_data(file_t *, int);

void *get_limit(file_t *) __nonnull ((1)) __wur;

/* Global Variables */
char		*prog_name;
off_t		EXIF_DATA_OFFSET;
file_t		infile;
void 		*lim;
unsigned	FLAGS;

#endif
