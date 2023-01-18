# examples/notification-demo/udp_to_dbus/Makefile
#
# Copyright (C) 2021-2023 wolfSSL Inc.
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

all: udp_to_dbus

ifndef WOLFSENTRY_ROOT
    WOLFSENTRY_ROOT=/usr/local/lib
endif

WOLFSENTRY_INCLUDEDIR := $(WOLFSENTRY_ROOT)/include
WOLFSENTRY_LIBDIR := $(WOLFSENTRY_ROOT)/lib

ifndef DIAGFLAGS
    DIAGFLAGS := -Wall -Wextra -ggdb
endif

ifndef OPTFLAGS
    OPTFLAGS := -O3
endif

udp_to_dbus.o: udp_to_dbus.c
	$(CC) $(CFLAGS) $(DIAGFLAGS) $(OPTFLAGS) -c $< $(shell pkg-config --cflags libnotify) -I$(WOLFSENTRY_INCLUDEDIR)

udp_to_dbus: udp_to_dbus.o
	$(CC) $(LDFLAGS) $(DIAGFLAGS) $(OPTFLAGS) -o $@ $+ $(shell pkg-config --libs libnotify) -ldl -lm -lpthread -L$(WOLFSENTRY_LIBDIR) -lwolfsentry

clean:
	$(RM) -f udp_to_dbus udp_to_dbus.o
