CC ?= gcc
AR ?= ar

WOLFSENTRY_PATH ?= ../../../wolfsentry
WOLFSENTRY_LIB ?= $(WOLFSENTRY_PATH)/libwolfsentry.a
WOLFIP_PATH ?= ../../../wolfip

CFLAGS ?= -O2 -g
CFLAGS += -D_GNU_SOURCE
CFLAGS += -DCONFIG_IPFILTER=1
CFLAGS += -Wall -Wextra -Wpedantic -std=c99
CFLAGS += -std=c99
CFLAGS += -I.
CFLAGS += -I./wolfip
CFLAGS += -I../../../wolfsentry/wolfsentry
CFLAGS += -I../../../wolfsentry
CFLAGS += -I$(WOLFIP_PATH)
CFLAGS += -I$(WOLFIP_PATH)/src
CFLAGS += -I$(WOLFIP_PATH)/src/port/posix
CFLAGS += -pthread

LDFLAGS ?= -pthread

TARGET := wolfip-wolfsentry-demo

APP_SRCS := main.c
APP_OBJS := $(APP_SRCS:.c=.o)

TAP_SRC := $(WOLFIP_PATH)/src/port/posix/tap_linux.c
TAP_OBJ := tap_linux.o

WOLFIP_SRC := $(WOLFIP_PATH)/src/wolfip.c
WOLFIP_LIB := libwolfip.a
WOLFIP_OBJ := wolfip.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(APP_OBJS) $(TAP_OBJ) $(WOLFIP_LIB) $(WOLFSENTRY_LIB)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

$(APP_OBJS): %.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TAP_OBJ): $(TAP_SRC) wolfip/config.h
	$(CC) $(CFLAGS) -c $< -o $@

$(WOLFIP_OBJ): $(WOLFIP_SRC) wolfip/config.h
	$(CC) $(CFLAGS) -c $< -o $@

$(WOLFIP_LIB): $(WOLFIP_OBJ)
	$(AR) rcs $@ $<

$(WOLFSENTRY_LIB):
	$(MAKE) -C $(WOLFSENTRY_PATH) libwolfsentry.a \
		WOLFIP=1 \
		WOLFIP_TOP=$(abspath $(WOLFIP_PATH)) \
		WOLFIP_CONFIG_DIR=$(abspath $(CURDIR)/wolfip)

clean:
	$(RM) $(APP_OBJS) $(TAP_OBJ) $(WOLFIP_OBJ) $(WOLFIP_LIB) $(TARGET)
