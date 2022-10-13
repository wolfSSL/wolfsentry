# to build with debugging messages:
# make -j EXTRA_CFLAGS='-DDEBUG_WOLFSENTRY -DDEBUG_HTTP'
#
# and with profuse debugging messages for each I/O op:
# make -j EXTRA_CFLAGS='-DDEBUG_WOLFSENTRY -DDEBUG_HTTP -DDEBUG_HTTP_IO'

all: log_server

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

ifndef OPTFLAGS
  OPTFLAGS := -Wall -Wextra -O2 -g
endif

CFLAGS += $(OPTFLAGS)

ifndef TARGET
  TARGET := linux
endif

ifeq ($(TARGET), linux)
  CFLAGS += -DBUILD_FOR_LINUX
  LDFLAGS += -Xlinker -rpath -Xlinker $(WOLFSSL_LIBDIR)
else ifeq ($(TARGET), macosx)
  CFLAGS += -DBUILD_FOR_MACOSX
  LDFLAGS += -Xlinker -rpath -Xlinker $(WOLFSSL_LIBDIR)
else
  $(error TARGET $(TARGET) is unknown -- use "linux" or "macosx")
endif

CFLAGS += $(EXTRA_CFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ -ggdb -I$(WOLFSENTRY_INCLUDEDIR) -I$(WOLFSSL_INCLUDEDIR)

log_server: log_server.o sentry.o $(DDS_OBJS)
	$(CC) $(LDFLAGS) -o $@ $+ -ldl -lpthread -L$(WOLFSENTRY_LIBDIR) -lwolfsentry -L$(WOLFSSL_LIBDIR) -lwolfssl

clean:
	$(RM) -f log_server *.o $(DDS_OBJS)
