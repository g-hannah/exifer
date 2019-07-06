DEBUG:=0
BUILD:=0.2.5
CC=gcc
WFLAGS=-Wall -Werror
CFILES=main.c exif.c file.c logging.c
OFILES=main.o exif.o file.o logging.o
BINARY=exif_wipe

.PHONY: clean

$(BINARY): $(OFILES)
	$(CC) -o $(BINARY) $(OFILES)

$(OFILES): $(CFILES)
ifeq ($(DEBUG),1)
	@echo Debug build $(BUILD)
	$(CC) -DDEBUG -c $(CFILES)
else
	@echo Production build $(BUILD)
	$(CC) -c $(CFILES)
endif

clean:
	rm *.o
