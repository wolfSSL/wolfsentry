# to build with debugging messages:
# make -j -f Makefile.linux EXTRA_CFLAGS='-DDEBUG_WOLFSENTRY -DDEBUG_HTTP'
#
# and with profuse debugging messages for each I/O op:
# make -j -f Makefile.linux EXTRA_CFLAGS='-DDEBUG_WOLFSENTRY -DDEBUG_HTTP -DDEBUG_HTTP_IO'

all: echo_server

ifndef WOLFSENTRY_ROOT
    WOLFSENTRY_ROOT=/usr/local
endif

ifndef WOLFSSL_ROOT
    WOLFSSL_ROOT=/usr/local
endif

WOLFSENTRY_INCLUDEDIR := $(WOLFSENTRY_ROOT)/include
WOLFSENTRY_LIBDIR := $(WOLFSENTRY_ROOT)/lib

WOLFSSL_INCLUDEDIR := $(WOLFSSL_ROOT)/include
WOLFSSL_LIBDIR := $(WOLFSSL_ROOT)/lib

CFLAGS += -DBUILD_FOR_LINUX

CFLAGS += $(EXTRA_CFLAGS)

%.o: CFLAGS += -Wall -Wextra -O3 -g

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ -ggdb -I$(WOLFSENTRY_INCLUDEDIR) -I$(WOLFSSL_INCLUDEDIR)

echo_server: echo.o sentry.o $(DDS_OBJS)
	$(CC) $(LDFLAGS) -o $@ $+ -ldl -lpthread -L$(WOLFSENTRY_LIBDIR) -lwolfsentry -L$(WOLFSSL_LIBDIR) -lwolfssl

clean:
	$(RM) -f echo_server *.o $(DDS_OBJS)
