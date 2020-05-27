
CC=gcc
CFLAGS=-g -O3 -Wall
LDFLAGS=-g

all: tstxtdump

tstxtdump: tstxtdump.o
	$(CC) $(LDFLAGS) tstxtdump.o -o tstxtdump

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

install: all
	mkdir -p ${DESTDIR}/usr/bin
	install -m 755 tstxtdump ${DESTDIR}/usr/bin

clean:
	rm -f *.o tstxtdump

