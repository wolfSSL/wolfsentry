all: udp_to_dbus

ifdef WOLFSENTRY_ROOT
    WOLFSENTRY_INCLUDEDIR := $(WOLFSENTRY_ROOT)/include
    WOLFSENTRY_LIBDIR := $(WOLFSENTRY_ROOT)/lib
else
    WOLFSENTRY_INCLUDEDIR := ../../..
    WOLFSENTRY_LIBDIR := ../../..
endif

udp_to_dbus.o: udp_to_dbus.c
	$(CC) $(CFLAGS) -c $< -ggdb $(shell pkg-config --cflags glib-2.0) $(shell pkg-config --cflags gdk-pixbuf-2.0) -I$(WOLFSENTRY_INCLUDEDIR)

udp_to_dbus: udp_to_dbus.o
	$(CC) $(LDFLAGS) -ggdb -o $@ $+ -lnotify $(shell pkg-config --libs glib-2.0) $(shell pkg-config --libs gdk-pixbuf-2.0) -L$(WOLFSENTRY_LIBDIR) -lwolfsentry

clean:
	$(RM) -f udp_to_dbus udp_to_dbus.o
