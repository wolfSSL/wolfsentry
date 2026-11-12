CC ?= gcc
AR ?= ar

WOLFSENTRY_PATH ?= ../../../wolfsentry
WOLFSENTRY_LIB ?= $(WOLFSENTRY_PATH)/libwolfsentry.a
WOLFSENTRY_CFLAGS ?= -std=c89 -pedantic -DWOLFSENTRY_C89 -Wno-variadic-macros -Wno-overlength-strings
WOLFIP_PATH ?= ../../../wolfip

CFLAGS ?= -O2 -g
CFLAGS += -D_GNU_SOURCE
CFLAGS += -DCONFIG_IPFILTER=1
CFLAGS += -Wall -Wextra -Wpedantic -std=c99 -DWOLFSENTRY_C89
CFLAGS += -I.
CFLAGS += -I./wolfip
CFLAGS += -I$(WOLFSENTRY_PATH)/wolfsentry
CFLAGS += -I$(WOLFSENTRY_PATH)
CFLAGS += -I$(WOLFIP_PATH)
CFLAGS += -I$(WOLFIP_PATH)/src
CFLAGS += -I$(WOLFIP_PATH)/src/port/posix
CFLAGS += -pthread

LDFLAGS ?= -pthread

TARGET := wolfip-wolfsentry-demo
GLUE_TEST := wolfip-glue-test

APP_SRCS := main.c
APP_OBJS := $(APP_SRCS:.c=.o)

TAP_SRC := $(WOLFIP_PATH)/src/port/posix/tap_linux.c
TAP_OBJ := tap_linux.o

WOLFIP_SRC := $(WOLFIP_PATH)/src/wolfip.c
WOLFIP_LIB := libwolfip.a
WOLFIP_OBJ := wolfip.o

.PHONY: all clean glue-test

all: $(TARGET)

$(TARGET): $(APP_OBJS) $(TAP_OBJ) $(WOLFIP_LIB) $(WOLFSENTRY_LIB)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

$(APP_OBJS) glue_test.o: $(WOLFSENTRY_LIB)

$(APP_OBJS): %.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

# the threading model comes from the library's wolfsentry_options.h, not a forced WOLFSENTRY_C89.
glue_test.o: glue_test.c
	$(CC) $(filter-out -DWOLFSENTRY_C89,$(CFLAGS)) -c $< -o $@

# links the glue against stand-ins for wolfIP's filter registration, not the stack.
$(GLUE_TEST): glue_test.o $(WOLFSENTRY_LIB)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

glue-test: $(GLUE_TEST)
	./$(GLUE_TEST)

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
		WOLFIP_CONFIG_DIR=$(abspath $(CURDIR)/wolfip) \
		EXTRA_CFLAGS+='$(WOLFSENTRY_CFLAGS)'

clean:
	$(RM) $(APP_OBJS) glue_test.o $(TAP_OBJ) $(WOLFIP_OBJ) $(WOLFIP_LIB) $(TARGET) $(GLUE_TEST)
