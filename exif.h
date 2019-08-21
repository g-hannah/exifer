#ifndef _EXIF_H
#define _EXIF_H	1

#ifdef WIN32
# define _EOL	"\r\n"
#else
# define _EOL "\n"
#endif

#define BUILD			"0.2.14"

#define clear_struct(s) memset((s), 0, sizeof(*(s)))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define APP1_MARKER		"\xff\xe1"
#define END_MARKER		"\xff\xd8"
#define SECTION_COL		"\e[38;5;31m"
#define INFO_COL			"  \e[3;01m\e[38;5;125m"

#define TYPE_BYTE				0x0001
#define TYPE_ASCII			0x0002
#define TYPE_SHORT			0x0003
#define TYPE_RATIONAL		0x0005
#define TYPE_COMMENT		0x0007
#define TYPE_SRATIONAL	0x000a

#define OUT_WIDTH				20
#define MAX_PATH_LEN		1024

typedef struct datum_t
{
	void			*tag_p;
	void			*type_p;
	void			*len_p;
	void			*offset_p;
	unsigned short	type;
	unsigned int	len;
	unsigned int	offset;
	void			*data_start;
	void			*data_end;
} datum_t;

typedef struct file_t
{
	char				fullpath[MAX_PATH_LEN];
	size_t			size;
	int					fd;
	void				*map;
	void				*map_end;
	void				*new_end;
} file_t;

#define WIPE_DATE			0x1u
#define WIPE_DEVICE		0x2u
#define WIPE_GPS			0x4u
#define WIPE_UID			0x8u
#define WIPE_COMMENT	0x10u
#define WIPE_MISC			0x20u
#define WIPE_ALL			0x40u

typedef struct Options Options;

int get_date_time(file_t *, int) __nonnull ((1)) __wur;
int get_gps_data(file_t *, int) __nonnull ((1)) __wur;
int get_make_model(file_t *, int) __nonnull ((1)) __wur;
int get_miscellaneous_data(file_t *, int) __nonnull ((1)) __wur;
int get_test(file_t *, int) __nonnull ((1)) __wur;

void *get_limit(file_t *) __nonnull ((1)) __wur;

/* Global Variables */
char			*prog_name;
off_t			EXIF_DATA_OFFSET;
file_t		infile;
void 			*lim;
unsigned	FLAGS;

#endif
