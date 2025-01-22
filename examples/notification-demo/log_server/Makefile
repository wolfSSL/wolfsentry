# examples/notification-demo/udp_to_dbus/Makefile
#
# Copyright (C) 2021-2025 wolfSSL Inc.
#
# This file is part of wolfSentry.
#
# wolfSentry is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSentry is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

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

ifndef DIAGFLAGS
  DIAGFLAGS := -Wall -Wextra -ggdb
endif

CFLAGS += $(DIAGFLAGS)

ifndef OPTFLAGS
  OPTFLAGS := -O3
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
