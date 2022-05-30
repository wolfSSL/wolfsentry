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

SHELL := /bin/bash

ifeq "$(V)" "1"
    override undefine VERY_QUIET
endif

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

ifdef USER_MAKE_CONF
    include $(USER_MAKE_CONF)
endif

SRCS := util.c internal.c addr_families.c routes.c events.c actions.c kv.c

ifndef SRC_TOP
    SRC_TOP := $(shell pwd -P)
else
    SRC_TOP := $(shell cd $(SRC_TOP) && pwd -P)
endif

ifndef BUILD_TOP
    BUILD_TOP := .
endif

ifndef DEBUG
    DEBUG := -ggdb
endif

ifndef OPTIM
    OPTIM := -O3
endif

CC_V := $(shell $(CC) -v 2>&1 | sed "s/'/'\\\\''/g")

CC_IS_GCC := $(shell if echo '$(CC_V)' | grep -q -i 'gcc version'; then echo 1; else echo 0; fi)

ifndef GCC
    ifeq "$(CC_IS_GCC)" "1"
        GCC := $(CC)
    else
        GCC := gcc
    endif
endif

ifndef CLANG
    CLANG := clang
endif

AR_VERSION := $(shell $(AR) --version 2>&1 | sed "s/'/'\\\\''/g")

AR_IS_GNU_AR := $(shell if echo '$(AR_VERSION)' | grep -q 'GNU'; then echo 1; else echo 0; fi)

ifndef C_WARNFLAGS
    C_WARNFLAGS := -Wall -Wextra -Werror -Wformat=2 -Winit-self -Wmissing-include-dirs -Wunknown-pragmas -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wconversion -Wstrict-prototypes -Wold-style-definition -Wmissing-declarations -Wmissing-format-attribute -Wpointer-arith -Woverlength-strings -Wredundant-decls -Winline -Winvalid-pch -Wdouble-promotion -Wvla -Wno-missing-field-initializers -Wno-bad-function-cast -Wno-type-limits
    ifeq "$(CC_IS_GCC)" "1"
        C_WARNFLAGS += -Wjump-misses-init -Wlogical-op
    endif
endif

CFLAGS := -I$(SRC_TOP) $(OPTIM) $(DEBUG) -MMD $(C_WARNFLAGS) $(EXTRA_CFLAGS)
LDFLAGS := $(EXTRA_LDFLAGS)

VISIBILITY_CFLAGS := -fvisibility=hidden -DHAVE_VISIBILITY=1
DYNAMIC_CFLAGS := -fpic
DYNAMIC_LDFLAGS := -shared

$(BUILD_TOP)/src/json/centijson_%.o: CFLAGS+=-DWOLFSENTRY -Wno-conversion -Wno-sign-conversion -Wno-sign-compare
$(BUILD_TOP)/src/json/centijson_%.So: CFLAGS+=-DWOLFSENTRY -Wno-conversion -Wno-sign-conversion -Wno-sign-compare

ifeq "$(NO_STDIO)" "1"
    CFLAGS += -DWOLFSENTRY_NO_STDIO
    NO_JSON := 1
endif

ifeq "$(NO_JSON)" "1"
    CFLAGS += -DWOLFSENTRY_NO_JSON
else
    SRCS += json/centijson_sax.c json/load_config.c
    ifneq "$(NO_JSON_DOM)" "1"
        CFLAGS += -DWOLFSENTRY_HAVE_JSON_DOM
        SRCS += json/centijson_dom.c json/centijson_value.c
    endif
endif

ifdef USER_SETTINGS_FILE
    CFLAGS += -DWOLFSENTRY_USER_SETTINGS_FILE=\"$(USER_SETTINGS_FILE)\"
endif

ifeq "$(SINGLETHREADED)" "1"
    CFLAGS += -DWOLFSENTRY_SINGLETHREADED
else
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

INSTALL_HEADERS := wolfsentry/wolfsentry.h wolfsentry/wolfsentry_errcodes.h wolfsentry/wolfsentry_af.h wolfsentry/wolfsentry_util.h wolfsentry/wolfsentry_json.h wolfsentry/centijson_sax.h wolfsentry/centijson_dom.h wolfsentry/centijson_value.h $(BUILD_TOP)/wolfsentry_options.h

all: $(BUILD_TOP)/$(LIB_NAME)

ifeq "$(AR_IS_GNU_AR)" "1"
    AR_FLAGS := Dcqs
else
    AR_FLAGS := cqs
endif

DYNLIB_NAME := libwolfsentry.so

ifdef BUILD_DYNAMIC
INSTALL_LIBS += $(BUILD_TOP)/$(DYNLIB_NAME)
all: $(BUILD_TOP)/$(DYNLIB_NAME)
endif

#https://stackoverflow.com/questions/3236145/force-gnu-make-to-rebuild-objects-affected-by-compiler-definition/3237349#3237349
BUILD_PARAMS := (echo 'CC_V:'; echo '$(CC_V)'; echo 'SRC_TOP: $(SRC_TOP)'; echo 'CFLAGS: $(CFLAGS) $(VISIBILITY_CFLAGS)'; echo 'LDFLAGS: $(LDFLAGS)'; echo 'AR_VERSION:'; echo '$(AR_VERSION)'; echo 'ARFLAGS: $(AR_FLAGS)')

.PHONY: force
$(BUILD_TOP)/.build_params: force
	@cd $(SRC_TOP) && [ -d .git ] || exit 0 && ([ -d .git/hooks ] || mkdir .git/hooks) && ([ -e .git/hooks/pre-push ] || ln -s ../../scripts/pre-push.sh .git/hooks/pre-push 2>/dev/null || exit 0)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
ifdef VERY_QUIET
	@$(BUILD_PARAMS) | cmp -s - $@ 2>/dev/null; cmp_ev=$$?; if [ $$cmp_ev != 0 ]; then $(BUILD_PARAMS) > $@; fi; exit 0
else
	@$(BUILD_PARAMS) | cmp -s - $@ 2>/dev/null; cmp_ev=$$?; if [ $$cmp_ev = 0 ]; then echo 'Build parameters unchanged.'; else $(BUILD_PARAMS) > $@; if [ $$cmp_ev = 1 ]; then echo 'Rebuilding with changed build parameters.'; else echo 'Building fresh.'; fi; fi; exit 0
endif

$(BUILD_TOP)/wolfsentry_options.h: $(SRC_TOP)/scripts/build_wolfsentry_options_h.awk $(BUILD_TOP)/.build_params
	@echo '$(CFLAGS)' | $< > $@

$(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.o)): $(BUILD_TOP)/.build_params $(BUILD_TOP)/wolfsentry_options.h $(SRC_TOP)/Makefile

INTERNAL_CFLAGS := -DBUILDING_LIBWOLFSENTRY

$(BUILD_TOP)/src/%.o: $(SRC_TOP)/src/%.c
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	@rm -f $(@:.o=.gcda)
ifeq "$(V)" "1"
	$(CC) $(INTERNAL_CFLAGS) $(CFLAGS) $(VISIBILITY_CFLAGS) -MF $(@:.o=.d) -c $< -o $@
else
ifndef VERY_QUIET
	@echo "$(CC) ... -o $@"
endif
	@$(CC) $(INTERNAL_CFLAGS) $(CFLAGS) $(VISIBILITY_CFLAGS) -MF $(@:.o=.d) -c $< -o $@
endif

$(BUILD_TOP)/$(LIB_NAME): $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.o))
ifdef VERY_QUIET
	@rm -f $@
	@$(AR) $(AR_FLAGS) $@ $+
else
	@rm -f $@
	$(AR) $(AR_FLAGS) $@ $+
endif


# again, but to build the shared object:
$(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.So)): $(BUILD_TOP)/.build_params $(SRC_TOP)/Makefile

$(BUILD_TOP)/src/%.So: $(SRC_TOP)/src/%.c
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
	@rm -f $(@:.So=.gcda)
ifeq "$(V)" "1"
	$(CC) $(INTERNAL_CFLAGS) $(CFLAGS) $(DYNAMIC_CFLAGS) $(VISIBILITY_CFLAGS) -MF $(@:.So=.Sd) -c $< -o $@
else
ifndef VERY_QUIET
	@echo "$(CC) ... -o $@"
endif
	@$(CC) $(INTERNAL_CFLAGS) $(CFLAGS) $(DYNAMIC_CFLAGS) $(VISIBILITY_CFLAGS) -MF $(@:.So=.Sd) -c $< -o $@
endif

$(BUILD_TOP)/$(DYNLIB_NAME): $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.So))
ifdef VERY_QUIET
	@$(CC) $(LD_FLAGS) $(DYNAMIC_LDFLAGS) -o $@ $+
else
	$(CC) $(LD_FLAGS) $(DYNAMIC_LDFLAGS) -o $@ $+
endif


UNITTEST_LIST := test_init test_rwlocks test_static_routes test_dynamic_rules test_user_values test_user_addr_families

ifneq "$(NO_JSON)" "1"
    UNITTEST_LIST += test_json
    TEST_JSON_CFLAGS:=-DTEST_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/test-config.json\" -DTEST_NUMERIC_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/test-config-numeric.json\"
    $(BUILD_TOP)/tests/test_json: override CFLAGS+=$(TEST_JSON_CFLAGS)
endif

$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)): UNITTEST_GATE=-D$(shell basename '$@' | tr '[:lower:]' '[:upper:]')
$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)): $(SRC_TOP)/tests/unittests.c $(BUILD_TOP)/$(LIB_NAME)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
ifeq "$(V)" "1"
	$(CC) $(INTERNAL_CFLAGS) $(CFLAGS) $(UNITTEST_GATE) $(LDFLAGS) -o $@ $+
else
ifndef VERY_QUIET
	@echo "$(CC) ... -o $@"
endif
	@$(CC) $(INTERNAL_CFLAGS) $(CFLAGS) $(UNITTEST_GATE) $(LDFLAGS) -o $@ $+
endif


UNITTEST_LIST_SHARED=test_all_shared
UNITTEST_SHARED_FLAGS := $(addprefix -D,$(shell echo '$(UNITTEST_LIST)' | tr '[:lower:]' '[:upper:]')) $(TEST_JSON_CFLAGS)

$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST_SHARED)): $(SRC_TOP)/tests/unittests.c $(BUILD_TOP)/$(DYNLIB_NAME)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
ifeq "$(V)" "1"
	$(CC) $(INTERNAL_CFLAGS) $(CFLAGS) $(UNITTEST_SHARED_FLAGS) $(LDFLAGS) -o $@ $+
else
ifndef VERY_QUIET
	@echo "$(CC) ... -o $@"
endif
	@$(CC) $(INTERNAL_CFLAGS) $(CFLAGS) $(UNITTEST_SHARED_FLAGS) $(LDFLAGS) -o $@ $+
endif

ifdef BUILD_DYNAMIC
$(BUILD_TOP)/.tested: $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST_SHARED))
endif


.PHONY: test
test: $(BUILD_TOP)/.tested

$(BUILD_TOP)/.tested: $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST))
ifdef VERY_QUIET
	@for test in $(basename $(UNITTEST_LIST)); do $(TEST_ENV) $(VALGRIND) "$(BUILD_TOP)/tests/$$test" >/dev/null; exitcode=$$?; if [ $$exitcode != 0 ]; then echo "$${test} failed" 1>&2; break; fi; done; exit $$exitcode
else
ifeq "$(V)" "1"
		@for test in $(basename $(UNITTEST_LIST)); do echo "$${test}:"; $(TEST_ENV) $(VALGRIND) "$(BUILD_TOP)/tests/$$test"; exitcode=$$?; if [ $$exitcode != 0 ]; then break; fi; echo "$${test} succeeded"; echo; done; if [ "$$exitcode" = 0 ]; then echo 'all subtests succeeded.'; else exit $$exitcode; fi
else
		@for test in $(basename $(UNITTEST_LIST)); do echo -n "$${test}..."; $(TEST_ENV) $(VALGRIND) "$(BUILD_TOP)/tests/$$test" >/dev/null; exitcode=$$?; if [ $$exitcode != 0 ]; then break; fi; echo ' succeeded'; done; if [ "$$exitcode" = 0 ]; then echo 'all subtests succeeded.'; else exit $$exitcode; fi
endif
endif
ifdef BUILD_DYNAMIC
	@for test in $(UNITTEST_LIST_SHARED); do LD_LIBRARY_PATH=$(BUILD_TOP) $(TEST_ENV) $(VALGRIND) "$(BUILD_TOP)/tests/$$test" >/dev/null || exit $?; done
ifndef VERY_QUIET
	@echo '$(UNITTEST_LIST_SHARED) succeeded.'
endif
endif
	@touch $(BUILD_TOP)/.tested

-include $(SRC_TOP)/Makefile.analyzers

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
install: $(BUILD_TOP)/.tested

.PHONY: install-untested
install-untested: all

install install-untested:
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
    VERSION := $(VERSION)$(shell git diff --quiet 2>/dev/null || [ $$? -ne 1 ] || echo "-dirty")
endif

EXAMPLE_FILES := $(shell find examples/Linux-LWIP/ examples/STM32-LWIP/ examples/STM32-LWIP-WOLFSSL/ -type f -a \( -name '*.[ch]' -o -name '*.md' -o -name CMakeLists.txt -o -name Dockerfile -o -name '*.yml' -o -name '*.json' \) -print)

DIST_FILES := LICENSING README.md ChangeLog.md Makefile scripts/build_wolfsentry_options_h.awk Makefile.analyzers wolfsentry/*.h src/wolfsentry_internal.h src/wolfsentry_ll.h $(addprefix src/,$(SRCS)) tests/unittests.c tests/test-config.json tests/test-config-numeric.json $(EXAMPLE_FILES)

.PHONY: dist
dist:
ifdef VERY_QUIET
	@cd $(SRC_TOP) && $(TAR) --transform 's~^~wolfsentry-$(VERSION)/~' --gzip -cf wolfsentry-$(VERSION).tgz $(DIST_FILES)
else
	cd $(SRC_TOP) && $(TAR) --transform 's~^~wolfsentry-$(VERSION)/~' --gzip -cf wolfsentry-$(VERSION).tgz $(DIST_FILES)
endif

dist-test: dist
	@[ -d $(BUILD_TOP)/dist-test ] || mkdir -p $(BUILD_TOP)/dist-test
ifdef VERY_QUIET
	@cd $(BUILD_TOP)/dist-test && $(TAR) -xf $(SRC_TOP)/wolfsentry-$(VERSION).tgz && cd wolfsentry-$(VERSION) && $(MAKE) --quiet test
else
	@cd $(BUILD_TOP)/dist-test && $(TAR) -xf $(SRC_TOP)/wolfsentry-$(VERSION).tgz && cd wolfsentry-$(VERSION) && $(MAKE) test
endif

dist-test-clean:
	@[ -d $(BUILD_TOP)/dist-test/wolfsentry-$(VERSION) ] && [ -f $(SRC_TOP)/wolfsentry-$(VERSION).tgz ] && cd $(BUILD_TOP)/dist-test && $(TAR) -tf $(SRC_TOP)/wolfsentry-$(VERSION).tgz | xargs $(RM) -f
	@[ -d $(BUILD_TOP)/dist-test/wolfsentry-$(VERSION) ] && $(MAKE) $(EXTRA_MAKE_FLAGS) -f $(THIS_MAKEFILE) BUILD_TOP=$(BUILD_TOP)/dist-test/wolfsentry-$(VERSION) clean && rmdir $(BUILD_TOP)/dist-test

CLEAN_RM_ARGS = -f $(BUILD_TOP)/.build_params $(BUILD_TOP)/wolfsentry_options.h $(BUILD_TOP)/.tested $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.o)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.So)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.d)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.Sd)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.gcno)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.gcda)) $(BUILD_TOP)/$(LIB_NAME) $(BUILD_TOP)/$(DYNLIB_NAME) $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)) $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST_SHARED)) $(addprefix $(BUILD_TOP)/tests/,$(addsuffix .d,$(UNITTEST_LIST))) $(addprefix $(BUILD_TOP)/tests/,$(addsuffix .d,$(UNITTEST_LIST_SHARED))) $(ANALYZER_BUILD_ARTIFACTS)

.PHONY: clean
clean:
ifdef VERY_QUIET
	@rm $(CLEAN_RM_ARGS)
else
	@rm $(CLEAN_RM_ARGS) && echo 'cleaned all targets and ephemera in $(BUILD_TOP)'
endif
	@[ "$(BUILD_TOP)" != "." ] && find $(BUILD_TOP) -depth -type d 2>/dev/null | xargs rmdir 2>/dev/null || exit 0

-include $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.d))
-include $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.Sd))
