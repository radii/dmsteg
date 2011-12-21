# Switch the comments on the following two lines to use a dynamic libcrypto (OpenSSL >= 1.1.0):
#LDFLAGS = -ldl -lcrypto
LDFLAGS = -ldl ../libcrypto.a

LDDMFLAGS = -ldevmapper
FLAGS = -Wall -g
CC=gcc
LD=gcc
PREFIX=/usr
HEADERS=src/steg.h Makefile

all: stegdisk stegsetup stegd stegctl

o/stegsetup.o: src/stegsetup.c $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/stegdisk.o: src/stegdisk.c src/stegdisk.h $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/stegd.o: src/stegd.c $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/stegctl.o: src/stegctl.c $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/file.o: src/file.c $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/core.o: src/core.c $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/stegdisk_back.o: src/stegdisk_back.c src/stegdisk.h $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/stegdisk_ext.o: src/stegdisk_ext.c src/stegdisk.h $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/aux.o: src/aux.c $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/ramlist_pthread.o: src/ramlist.c $(HEADERS)
	$(CC) $(FLAGS) -DREENTRANT -c -o $@ src/ramlist.c
o/ramlist.o: src/ramlist.c $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/bunny.o: src/bunny.c $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/dm.o: src/dm.c $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))
o/stegd_lib.o: src/stegd_lib.c $(HEADERS)
	$(CC) $(FLAGS) -c -o $@ $(subst o/,src/,$(subst .o,.c,$@))

stegdisk: o/file.o o/core.o o/stegdisk_back.o o/stegdisk_ext.o o/aux.o o/bunny.o o/stegdisk.o o/ramlist.o
	$(LD) -o stegdisk o/file.o o/core.o o/stegdisk_back.o o/stegdisk_ext.o o/aux.o o/bunny.o o/stegdisk.o o/ramlist.o $(LDFLAGS) 
stegsetup: o/file.o o/core.o o/aux.o o/bunny.o o/dm.o o/stegd_lib.o o/stegsetup.o o/ramlist.o
	$(LD) -o stegsetup o/file.o o/core.o o/aux.o o/bunny.o o/dm.o o/stegd_lib.o o/stegsetup.o o/ramlist.o $(LDDMFLAGS) $(LDFLAGS)
stegd: o/aux.o o/bunny.o o/dm.o o/stegd.o o/ramlist_pthread.o
	$(LD) -o stegd o/aux.o o/bunny.o o/dm.o o/stegd.o o/ramlist_pthread.o -pthread $(LDDMFLAGS) $(LDFLAGS) 
stegctl: o/aux.o o/stegd_lib.o o/stegctl.o o/ramlist.o
	$(LD) -o stegctl o/aux.o o/stegd_lib.o o/stegctl.o o/ramlist.o

clean:
	rm -f stegdisk
	rm -f stegsetup
	rm -f stegd
	rm -f stegctl
	rm -f o/*
dist: clean
	tar -C .. -czf ../steg" - `date +%s`".tar.gz steg

install: all
	install -g 0 -o 0 -m 755 -p -T stegdisk $(PREFIX)/bin/stegdisk
	install -g 0 -o 0 -m 755 -p -T stegsetup $(PREFIX)/bin/stegsetup
	install -g 0 -o 0 -m 755 -p -T stegd $(PREFIX)/bin/stegd
	install -g 0 -o 0 -m 755 -p -T stegctl $(PREFIX)/bin/stegctl
	install -g 0 -o 0 -m 755 -p -T stegmount $(PREFIX)/bin/stegmount
	install -g 0 -o 0 -m 755 -p -T stegumount $(PREFIX)/bin/stegumount
