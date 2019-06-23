#ifndef _EXIF_H
#define _EXIF_H	1

#ifdef WIN32
# define _EOL	"\r\n"
#else
# define _EOL "\n"
#endif

#define BUILD			"0.2.3"

/*
 * TODO: Reliably determine the end of
 * the EXIF data so that we do not
 * match random binary data within the
 * image whilst trying to find EXIF
 * tags ...
 */
#define APP1_MARKER		"\xff\xe1"
#define END_MARKER		"\xff\xd8"
#define SECTION_COL		"\e[4;01m\e[38;5;245m"
#define INFO_COL			"  \e[3;01m\e[38;5;125m"

#define TYPE_ASCII			0x0002
#define TYPE_SHORT			0x0003
#define TYPE_RATIONAL		0x0005
#define TYPE_COMMENT		0x0007
#define TYPE_SRATIONAL	0x000a

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
#define WIPE_LOCATION	0x4u
#define WIPE_UID			0x8u
#define WIPE_COMMENT	0x10u
#define WIPE_ALL			0x20u

typedef struct Options Options;

int get_date_time(file_t *, int) __nonnull ((1)) __wur;
int get_latitude(file_t *, int) __nonnull ((1)) __wur;
int get_make_model(file_t *, int) __nonnull ((1)) __wur;
int get_unique_id(file_t *, int) __nonnull ((1)) __wur;
int get_image_comment(file_t *, int) __nonnull ((1)) __wur;
int get_test(file_t *, int) __nonnull ((1)) __wur;

void *get_limit(file_t *) __nonnull ((1)) __wur;

/* Global Variables */
char			*prog_name;
off_t			EXIF_DATA_OFFSET;
file_t		infile;
void 			*lim;
unsigned	FLAGS;

#endif
