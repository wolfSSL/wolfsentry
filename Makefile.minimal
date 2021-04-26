# Makefile
#
# Copyright (C) 2021 wolfSSL Inc.
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

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

ifdef USER_MAKE_CONF
    include $(USER_MAKE_CONF)
endif

SRCS = util.c internal.c routes.c events.c actions.c

ifndef BUILD_TOP
    BUILD_TOP := .
endif

ifndef DEBUG
    DEBUG := -ggdb
endif

ifndef OPTIM
    OPTIM := -O3
endif

CC_IS_GCC := $(shell if $(CC) -v 2>&1 | grep -q -i 'gcc version'; then echo 1; else echo 0; fi)

ifndef C_WARNFLAGS
    C_WARNFLAGS := -Wall -Wextra -Werror -Wformat=2 -Winit-self -Wmissing-include-dirs -Wunknown-pragmas -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wconversion -Wstrict-prototypes -Wold-style-definition -Wmissing-declarations -Wmissing-format-attribute -Wpointer-arith -Woverlength-strings -Wredundant-decls -Winline -Winvalid-pch -Wdouble-promotion -Wvla -Wno-missing-field-initializers -Wno-bad-function-cast
    ifeq "$(CC_IS_GCC)" "1"
        C_WARNFLAGS += -Wjump-misses-init -Wlogical-op
    endif
endif

CFLAGS := -I. $(OPTIM) $(DEBUG) -MMD $(C_WARNFLAGS) $(EXTRA_CFLAGS)
LDFLAGS := $(EXTRA_LDFLAGS)

ifdef USER_SETTINGS_FILE
    CFLAGS += -DWOLFSENTRY_USER_SETTINGS_FILE=\"$(USER_SETTINGS_FILE)\"
endif

ifeq "$(SINGLETHREADED)" "1"
    CFLAGS += -DWOLFSENTRY_SINGLETHREADED
endif

ifneq "$(SINGLETHREADED)" "1"
    LDFLAGS += -pthread
endif

ifeq "$(STATIC)" "1"
    LDFLAGS += -static
endif

ifeq "$(STRIPPED)" "1"
    DEBUG :=
    CFLAGS += -ffunction-sections -fdata-sections
    LDFLAGS += -Wl,--gc-sections -Wl,--strip-all
endif

.PHONY: all

LIB_NAME := libwolfsentry.a

INSTALL_LIBS := $(BUILD_TOP)/$(LIB_NAME)

INSTALL_HEADERS := wolfsentry/wolfsentry.h wolfsentry/wolfsentry_errcodes.h

all: $(BUILD_TOP)/$(LIB_NAME)

$(BUILD_TOP)/src/%.o: src/%.c
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
ifeq "$(V)" "1"
	$(CC) $(CFLAGS) -MF $(BUILD_TOP)/$(<:.c=.d) -c $< -o $@
else
ifndef VERY_QUIET
	@echo "$(CC) ... -o $@"
endif
	@$(CC) $(CFLAGS) -MF $(BUILD_TOP)/$(<:.c=.d) -c $< -o $@
endif

$(BUILD_TOP)/$(LIB_NAME): $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.o))
ifdef VERY_QUIET
	@$(AR) crs $@ $+
else
	$(AR) crs $@ $+
endif

UNITTEST_LIST := test_init test_rwlocks test_static_routes test_dynamic_rules

$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)): UNITTEST_GATE=-D$(shell basename '$@' | tr '[:lower:]' '[:upper:]')
$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)): tests/unittests.c $(BUILD_TOP)/$(LIB_NAME)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
ifeq "$(V)" "1"
	$(CC) $(CFLAGS) $(UNITTEST_GATE) $(LDFLAGS) -o $@ $+
else
ifndef VERY_QUIET
	@echo "$(CC) ... -o $@"
endif
	@$(CC) $(CFLAGS) $(UNITTEST_GATE) $(LDFLAGS) -o $@ $+
endif

.PHONY: test
test: $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST))
ifdef VERY_QUIET
	@for test in $(basename $(UNITTEST_LIST)); do $(TEST_ENV) $(VALGRIND) "$(BUILD_TOP)/tests/$$test" >/dev/null; exitcode=$$?; if [ $$exitcode != 0 ]; then echo "$${test} failed" 1>&2; break; fi; done; exit $$exitcode
else
	@for test in $(basename $(UNITTEST_LIST)); do echo "$${test}:"; $(TEST_ENV) $(VALGRIND) "$(BUILD_TOP)/tests/$$test"; exitcode=$$?; if [ $$exitcode != 0 ]; then break; fi; echo "$${test} succeeded"; echo; done; if [ "$$exitcode" = 0 ]; then echo 'all tests succeeded.'; else exit $$exitcode; fi
endif

-include Makefile.analyzers

ifndef INSTALL_DIR
    INSTALL_DIR := /usr/local
endif

ifndef INSTALL_LIBDIR
    INSTALL_LIBDIR := $(INSTALL_DIR)/lib
endif

ifndef INSTALL_INCDIR
    INSTALL_INCDIR := $(INSTALL_DIR)/include
endif

.PHONY: install
install: all
	@mkdir -p $(INSTALL_LIBDIR)
	install -p -m 0644 $(INSTALL_LIBS) $(INSTALL_LIBDIR)
	@mkdir -p $(INSTALL_INCDIR)/wolfsentry
	install -p -m 0644 $(INSTALL_HEADERS) $(INSTALL_INCDIR)/wolfsentry

.PHONY: uninstall
uninstall:
	$(RM) $(addprefix $(INSTALL_LIBDIR)/,$(notdir $(INSTALL_LIBS))) $(addprefix $(INSTALL_INCDIR)/,$(INSTALL_HEADERS))
	@rmdir $(INSTALL_LIBDIR) $(INSTALL_INCDIR)/wolfsentry $(INSTALL_INCDIR) 2>/dev/null || exit 0

# $(TAR) must be gnu tar, for its --transform capability.  This is the default on Linux, but on Mac,
# it will need to be installed, and TAR=gtar will be needed.
ifndef TAR
    TAR := tar
endif

ifndef VERSION
    VERSION := $(shell git rev-parse --short=8 HEAD 2>/dev/null || echo xxxxxxxx)
    VERSION := $(VERSION)$(shell git diff --quiet || [ $$? -ne 1 ] || echo "-dirty")
endif

.PHONY: dist
dist:
	$(TAR) --transform 's~^~wolfsentry-$(VERSION)/~' --gzip -cf wolfsentry-$(VERSION).tgz README.md Makefile Makefile.minimal wolfsentry/ src/wolfsentry_internal.h $(addprefix src/,$(SRCS)) tests/unittests.c

.PHONY: clean
clean:
	rm -f $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.o)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.d)) $(BUILD_TOP)/$(LIB_NAME) $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)) $(addprefix $(BUILD_TOP)/tests/,$(addsuffix .d,$(UNITTEST_LIST)))
	@[ "$(BUILD_TOP)" != "." ] && rmdir $(BUILD_TOP)/* $(BUILD_TOP) 2>/dev/null || exit 0

-include $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.d))
