PREFIX	 = /usr/local
OBJS	 = blocks.o \
	   child.o \
	   client.o \
	   downloader.o \
	   fargs.o \
	   flist.o \
	   hash.o \
	   ids.o \
	   io.o \
	   log.o \
	   md4.o \
	   mkpath.o \
	   mktemp.o \
	   receiver.o \
	   sender.o \
	   server.o \
	   session.o \
	   socket.o \
	   symlinks.o \
	   uploader.o
ALLOBJS	 = $(OBJS) \
	   main.o
AFLS	 = afl/test-blk_recv \
	   afl/test-flist_recv
MANDIR	 = $(PREFIX)/man
BINDIR	 = $(PREFIX)/bin

# The -O0 is to help with debugging coredumps.
CFLAGS	+= -O0 -g -W -Wall -Wextra -Wno-unused-parameter
LDFLAGS = -lm

# Linux-specific configuration
ifeq ($(shell uname -s),Linux)
	# Include the libbsd compatibility library on Linux
	CFLAGS += $(shell pkg-config --cflags libbsd) -D_GNU_SOURCE
	LDFLAGS += $(shell pkg-config --libs libbsd)

	# Include the implementation of Linux compatibility wrappers
	OBJS += linux.o seccomp_broker.o
endif

all: openrsync

openrsync: $(ALLOBJS)
	$(CC) -o $@ $(ALLOBJS) $(LDFLAGS)

afl: $(AFLS)

$(AFLS): $(OBJS)
	$(CC) -o $@ $*.c $(OBJS)

install: openrsync
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(MANDIR)/man5
	install -m 0444 openrsync.1 $(DESTDIR)$(MANDIR)/man1
	install -m 0444 rsync.5 rsyncd.5 $(DESTDIR)$(MANDIR)/man5
	install -m 0555 openrsync $(DESTDIR)$(BINDIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/openrsync
	rm -f $(DESTDIR)$(MANDIR)/man1/openrsync.1
	rm -f $(DESTDIR)$(MANDIR)/man5/rsync.5
	rm -f $(DESTDIR)$(MANDIR)/man5/rsyncd.5

clean:
	rm -f $(ALLOBJS) openrsync $(AFLS)

$(ALLOBJS) $(AFLS): extern.h

blocks.o downloader.o hash.o md4.o: md4.h
