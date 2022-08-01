all: udp_to_dbus

ifndef WOLFSENTRY_ROOT
    $(error WOLFSENTRY_ROOT is not set)
endif

WOLFSENTRY_INCLUDEDIR := $(WOLFSENTRY_ROOT)/include
WOLFSENTRY_LIBDIR := $(WOLFSENTRY_ROOT)/lib

udp_to_dbus.o: udp_to_dbus.c
	$(CC) $(CFLAGS) -c $< -ggdb $(shell pkg-config --cflags libnotify) -I$(WOLFSENTRY_INCLUDEDIR)

udp_to_dbus: udp_to_dbus.o
	$(CC) $(LDFLAGS) -ggdb -o $@ $+ $(shell pkg-config --libs libnotify) -L$(WOLFSENTRY_LIBDIR) -lwolfsentry

clean:
	$(RM) -f udp_to_dbus udp_to_dbus.o
