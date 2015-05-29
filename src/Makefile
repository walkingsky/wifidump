PROGS     = wifidump

INSTDIR   = $(prefix)/usr/bin
INSTMODE  = 0755
INSTOWNER = root
INSTGROUP = root

OBJS = main.o
#CC = $(CC) -EB
all: $(PROGS)
$(PROGS): $(OBJS)
	$(CC)  $(CFLAGS) $(LDFLAGS) $^  -lpcap -lsqlite3  -o $@
	$(STRIP) $@

%.o: %.c
	$(CC)  -c $(CFLAGS) $^ -o $@

install: $(PROGS)
	$(INSTALL) -d $(INSTDIR)
	$(INSTALL) -m $(INSTMODE) -o $(INSTOWNER) -g $(INSTGROUP) $(PROGS) $(INSTDIR)

clean:
	rm -f $(PROGS) *.o core

