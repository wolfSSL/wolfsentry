# Makefile
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

SHELL := bash
AWK := awk

 Q?=@
ifeq "$(V)" "1"
    override undefine VERY_QUIET
    Q=
endif

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

ifdef USER_MAKE_CONF
    include $(USER_MAKE_CONF)
endif

SRCS := wolfsentry_util.c wolfsentry_internal.c addr_families.c routes.c events.c actions.c kv.c action_builtins.c

# Set PWD command based on OS - Windows uses 'pwd', others use 'pwd -P'
ifeq ($(OS),Windows_NT)
    PWD := pwd
    SRC_TOP := .
else
    PWD := pwd -P
    ifndef SRC_TOP
        SRC_TOP := $(shell $(PWD))
    else
        SRC_TOP := $(shell cd $(SRC_TOP) && $(PWD))
    endif
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

ifndef NM
    NM := nm
endif

ifdef HOST
    ifeq "$(CC)" "cc"
        CC = $(HOST)-gcc
    endif
    ifeq "$(CXX)" "c++"
        CXX = $(HOST)-g++
    endif
    ifeq "$(CPP)" "cpp"
        CPP = $(HOST)-cpp
    endif
    ifeq "$(LD)" "ld"
        LD = $(HOST)-gcc
    endif
    ifeq "$(AR)" "ar"
        AR = $(HOST)-ar
    endif
    ifeq "$(AS)" "as"
        AS = $(HOST)-as
    endif
    ifeq "$(NM)" "nm"
        NM = $(HOST)-nm
    endif
endif

ifdef RUNTIME
    ifeq "$(RUNTIME)" "FreeRTOS-lwIP"
        ifndef FREERTOS_TOP
            $(error FREERTOS_TOP not supplied with RUNTIME=$(RUNTIME))
        endif
        ifndef LWIP
            LWIP := 1
        endif
        RUNTIME_CFLAGS += -DFREERTOS -DWOLFSENTRY_NO_GETPROTOBY -DWOLFSENTRY_NO_POSIX_MEMALIGN -ffreestanding -I$(FREERTOS_TOP)/FreeRTOS/Source/include -I$(FREERTOS_TOP)/FreeRTOS/Source/portable/GCC/ARM_CM3
    else ifeq "$(RUNTIME)" "Linux-lwIP"
        ifndef LWIP
            LWIP := 1
        endif
    else ifeq "$(RUNTIME)" "ThreadX-NetXDuo"
        ifndef THREADX_TOP
            $(error THREADX_TOP not supplied with RUNTIME=$(RUNTIME))
        endif
        ifndef NETXDUO
            NETXDUO := 1
        endif
        RUNTIME_CFLAGS += -DTHREADX -I$(THREADX_TOP)
        ifdef NEED_THREADX_TYPES
            RUNTIME_CFLAGS += -DNEED_THREADX_TYPES -I$(THREADX_TYPES_TOP)
        endif
    else
        $(error unrecognized runtime "$(RUNTIME)")
    endif
else
    RUNTIME := $(shell uname -s)
endif

RUNTIME_CFLAGS += $(shell [ -d "$(SRC_TOP)/ports/$(RUNTIME)/include/" ] && echo -I$(SRC_TOP)/ports/$(RUNTIME)/include)

ifdef LWIP
        ifndef LWIP_TOP
            $(error LWIP_TOP not supplied with LWIP enabled)
        endif
        LWIP_CFLAGS += -DWOLFSENTRY_LWIP -I$(LWIP_TOP)/src/include -D_NETINET_IN_H -DWOLFSENTRY_NO_GETPROTOBY
        SRCS += lwip/packet_filter_glue.c
endif

ifdef NETXDUO
        ifndef NETXDUO_TOP
            NETXDUO_TOP=$(THREADX_TOP)
        endif
        LWIP_CFLAGS += -DWOLFSENTRY_NETXDUO -I$(NETXDUO_TOP) -D_NETINET_IN_H -DWOLFSENTRY_NO_GETPROTOBY
endif

CC_V := $(shell $(CC) -v 2>&1 | sed "s/[\`']/'\\\\''/g")

CC_IS_GCC := $(shell if [[ '$(CC_V)' =~ 'gcc version' ]]; then echo 1; else echo 0; fi)

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

AS_VERSION := $(shell $(AS) --version 2>&1 | sed "s/[\`']/'\\\\''/g")
LD_VERSION := $(shell $(LD) --version 2>&1 | sed "s/[\`']/'\\\\''/g")
AR_VERSION := $(shell $(AR) --version 2>&1 | sed "s/[\`']/'\\\\''/g")

AR_IS_GNU_AR := $(shell if [[ '$(AR_VERSION)' =~ 'GNU' ]]; then echo 1; else echo 0; fi)

ifndef C_WARNFLAGS
    C_WARNFLAGS := -Wall -Wextra -Werror -Wformat=2 -Winit-self -Wmissing-include-dirs -Wunknown-pragmas -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wconversion -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-declarations -Wmissing-format-attribute -Wpointer-arith -Woverlength-strings -Wredundant-decls -Winline -Winvalid-pch -Wdouble-promotion -Wvla -Wno-type-limits -Wdeclaration-after-statement -Wnested-externs
    ifeq "$(CC_IS_GCC)" "1"
        MAYBE_WARN_PACKED_NOT_ALIGNED := $(shell $(CC) -E -Wpacked-not-aligned -x c /dev/null >/dev/null 2>&1 && echo -Wpacked-not-aligned)
        C_WARNFLAGS += -Wjump-misses-init -Wlogical-op -Wlogical-not-parentheses $(MAYBE_WARN_PACKED_NOT_ALIGNED)
    endif
endif

CFLAGS := -I$(BUILD_TOP) -I$(SRC_TOP) $(OPTIM) $(DEBUG) $(C_WARNFLAGS) $(LWIP_CFLAGS) $(RUNTIME_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS := $(EXTRA_LDFLAGS)

VISIBILITY_CFLAGS := -fvisibility=hidden -DHAVE_VISIBILITY=1
DYNAMIC_CFLAGS := -fpic
DYNAMIC_LDFLAGS := -shared

ifdef NO_STDIO_STREAMS
    CFLAGS += -DWOLFSENTRY_NO_STDIO_STREAMS
endif

ifdef NO_ADDR_BITMASK_MATCHING
    CFLAGS += -DWOLFSENTRY_NO_ADDR_BITMASK_MATCHING
endif

ifdef NO_IPV6
    CFLAGS += -DWOLFSENTRY_NO_IPV6
endif

# JSON settings need to be extracted from $(USER_SETTINGS_FILE) to determine if JSON sources should be built.
ifdef USER_SETTINGS_FILE
    ifeq "$(shell grep -q -E -e '^#define WOLFSENTRY_NO_JSON$$' '$(USER_SETTINGS_FILE)' && echo 1 || echo 0)" "1"
        USER_SETTINGS_NO_JSON := 1
    endif
    ifeq "$(shell grep -q -E -e '^#define WOLFSENTRY_NO_JSON_DOM$$' '$(USER_SETTINGS_FILE)' && echo 1 || echo 0)" "1"
        USER_SETTINGS_NO_JSON_DOM := 1
    endif
endif

ifdef NO_JSON
    CFLAGS += -DWOLFSENTRY_NO_JSON -DWOLFSENTRY_NO_JSON_DOM
else ifdef USER_SETTINGS_NO_JSON
    NO_JSON := 1
else
    SRCS += json/centijson_sax.c json/json_util.c json/load_config.c
    ifdef NO_JSON_DOM
        CFLAGS += -DWOLFSENTRY_NO_JSON_DOM
    else ifdef USER_SETTINGS_NO_JSON_DOM
        NO_JSON_DOM := 1
    else
        SRCS += json/centijson_dom.c json/centijson_value.c
    endif
endif

ifdef CALL_TRACE
    CFLAGS += -DWOLFSENTRY_DEBUG_CALL_TRACE -fno-omit-frame-pointer -Wno-inline
endif

ifdef SINGLETHREADED
    CFLAGS += -DWOLFSENTRY_SINGLETHREADED
else
    ifeq "$(RUNTIME)" "ThreadX-NetXDuo"
    else ifeq "$(RUNTIME)" "FreeRTOS-lwIP"
    else
        LDFLAGS += -pthread
    endif
endif

ifdef USER_SETTINGS_FILE
    ifneq (,$(filter -D% -U%,$(CFLAGS)))
        $(error $(filter -D% -U%,$(CFLAGS)) USER_SETTINGS_FILE can't be combined with make-based feature switches or EXTRA_CFLAGS with macro clauses)
    endif
    CFLAGS += -DWOLFSENTRY_USER_SETTINGS_FILE=\"$(USER_SETTINGS_FILE)\"
endif

ifdef STATIC
    LDFLAGS += -static
endif

ifdef STRIPPED
    DEBUG :=
    LDFLAGS += -Wl,--strip-all
endif

ifdef FUNCTION_SECTIONS
    CFLAGS += -ffunction-sections -fdata-sections
    LDFLAGS += -Wl,--gc-sections
endif

.PHONY: all

LIB_NAME := libwolfsentry.a

INSTALL_LIBS := $(BUILD_TOP)/$(LIB_NAME)

INSTALL_HEADERS := wolfsentry/wolfsentry.h wolfsentry/wolfsentry_settings.h wolfsentry/wolfsentry_errcodes.h wolfsentry/wolfsentry_af.h wolfsentry/wolfsentry_util.h wolfsentry/wolfsentry_json.h wolfsentry/centijson_sax.h wolfsentry/centijson_dom.h wolfsentry/centijson_value.h wolfsentry/wolfssl_test.h

ifdef USER_SETTINGS_FILE
    OPTIONS_FILE := $(USER_SETTINGS_FILE)
else
    OPTIONS_FILE := $(BUILD_TOP)/wolfsentry/wolfsentry_options.h
    INSTALL_HEADERS += $(OPTIONS_FILE)
endif

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
BUILD_PARAMS := (echo 'CC_V:'; echo '$(CC_V)'; echo 'SRC_TOP: $(SRC_TOP)'; echo 'CFLAGS: $(CFLAGS) $(VISIBILITY_CFLAGS)'; echo 'LDFLAGS: $(LDFLAGS)'; echo 'AS_VERSION:'; echo '$(AS_VERSION)'; echo 'LD_VERSION:'; echo '$(LD_VERSION)'; echo 'AR_VERSION:'; echo '$(AR_VERSION)'; echo 'ARFLAGS: $(AR_FLAGS)')

.PHONY: force
$(BUILD_TOP)/.build_params: force
	$(Q)cd $(SRC_TOP) && [ -d .git ] || exit 0 && ([ -d .git/hooks ] || mkdir .git/hooks) && ([ -e .git/hooks/pre-push ] || ln -s ../../scripts/pre-push.sh .git/hooks/pre-push 2>/dev/null || exit 0)
	$(Q)[ -d $(dir $@) ] || mkdir -p $(dir $@)
ifdef VERY_QUIET
	$(Q){ $(BUILD_PARAMS) | cmp -s - $@; } 2>/dev/null; cmp_ev=$$?; if [ $$cmp_ev != 0 ]; then $(BUILD_PARAMS) > $@; fi; exit 0
else
	$(Q){ $(BUILD_PARAMS) | cmp -s - $@; } 2>/dev/null; cmp_ev=$$?; if [ $$cmp_ev = 0 ]; then echo 'Build parameters unchanged.'; else $(BUILD_PARAMS) > $@; if [ $$cmp_ev = 1 ]; then echo 'Rebuilding with changed build parameters.'; else echo 'Building fresh.'; fi; fi; exit 0
endif

ifndef USER_SETTINGS_FILE
$(BUILD_TOP)/wolfsentry/wolfsentry_options.h: $(SRC_TOP)/scripts/build_wolfsentry_options_h.awk $(BUILD_TOP)/.build_params
	$(Q)[ -d $(BUILD_TOP)/wolfsentry ] || mkdir -p $(BUILD_TOP)/wolfsentry
	$(Q)echo '$(CFLAGS)' | $(AWK) -f $< > $@
endif

$(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.o)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.So)): $(BUILD_TOP)/.build_params $(OPTIONS_FILE) $(SRC_TOP)/Makefile

INTERNAL_CFLAGS := -DBUILDING_LIBWOLFSENTRY -MMD

$(BUILD_TOP)/src/%.o: $(SRC_TOP)/src/%.c
	$(Q)[ -d $(dir $@) ] || mkdir -p $(dir $@)
	$(Q)rm -f $(@:.o=.gcda)
ifndef VERY_QUIET
	$(Q)echo "$(CC) ... -o $@"
endif
	$(Q)$(CC) $(INTERNAL_CFLAGS) $(CFLAGS) $(VISIBILITY_CFLAGS) -MF $(@:.o=.d) -c $< -o $@

$(BUILD_TOP)/$(LIB_NAME): $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.o))
	$(Q)rm -f $@
	$(Q)$(AR) $(AR_FLAGS) $@ $+


# again, but to build the shared object:
$(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.So)): $(BUILD_TOP)/.build_params $(SRC_TOP)/Makefile

$(BUILD_TOP)/src/%.So: $(SRC_TOP)/src/%.c
	$(Q)[ -d $(dir $@) ] || mkdir -p $(dir $@)
	$(Q)rm -f $(@:.So=.gcda)
ifndef VERY_QUIET
	$(Q)echo "$(CC) ... -o $@"
endif
	$(Q)$(CC) $(INTERNAL_CFLAGS) $(CFLAGS) $(DYNAMIC_CFLAGS) $(VISIBILITY_CFLAGS) -MF $(@:.So=.Sd) -c $< -o $@

$(BUILD_TOP)/$(DYNLIB_NAME): $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.So))
	$(Q)$(CC) $(LD_FLAGS) $(DYNAMIC_LDFLAGS) -o $@ $+

UNITTEST_LIST := test_init test_rwlocks test_static_routes test_dynamic_rules test_user_values test_user_addr_families $(UNITTEST_LIST_EXTRAS)

ifneq "$(NO_JSON)" "1"
    UNITTEST_LIST += test_json
    ifndef NO_JSON_DOM
        UNITTEST_LIST += $(UNITTEST_LIST_JSON_DOM_EXTRAS)
        TEST_JSON_CFLAGS := -DTEST_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/test-config.json\" -DEXTRA_TEST_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/extra-test-config.json\" -DTEST_NUMERIC_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/test-config-numeric.json\"
    else ifndef TEST_JSON_CFLAGS
        TEST_JSON_CFLAGS := -DTEST_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/test-config-no-dom.json\" -DEXTRA_TEST_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/extra-test-config.json\" -DTEST_NUMERIC_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/test-config-numeric-no-dom.json\"
    endif
    $(BUILD_TOP)/tests/test_json: override CFLAGS+=$(TEST_JSON_CFLAGS)
endif

$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)): UNITTEST_GATE=-D$(shell basename '$@' | tr '[:lower:]' '[:upper:]')
$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)): $(SRC_TOP)/tests/unittests.c $(BUILD_TOP)/$(LIB_NAME) $(OPTIONS_FILE)
	$(Q)[ -d $(dir $@) ] || mkdir -p $(dir $@)
ifndef VERY_QUIET
	$(Q)echo "$(CC) ... -o $@"
endif
	$(Q)$(CC) $(CFLAGS) $(UNITTEST_GATE) $(LDFLAGS) -o $@ $(filter-out %.h,$^)


UNITTEST_LIST_SHARED=test_all_shared
UNITTEST_SHARED_FLAGS := $(addprefix -D,$(shell echo '$(UNITTEST_LIST)' | tr '[:lower:]' '[:upper:]')) $(TEST_JSON_CFLAGS)

$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST_SHARED)): $(SRC_TOP)/tests/unittests.c $(BUILD_TOP)/$(DYNLIB_NAME) $(OPTIONS_FILE)
	$(Q)[ -d $(dir $@) ] || mkdir -p $(dir $@)
ifndef VERY_QUIET
	$(Q)echo "$(CC) ... -o $@"
endif
	$(Q)$(CC) $(CFLAGS) $(UNITTEST_SHARED_FLAGS) $(LDFLAGS) -o $@ $< $(BUILD_TOP)/$(DYNLIB_NAME)

ifdef BUILD_DYNAMIC
$(BUILD_TOP)/.tested: $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST_SHARED))
endif


.PHONY: test
test: $(BUILD_TOP)/.tested

$(BUILD_TOP)/.tested: $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST))
ifdef VERY_QUIET
	$(Q)for test in $(basename $(UNITTEST_LIST)); do $(TEST_ENV) $(EXE_LAUNCHER) "$(BUILD_TOP)/tests/$$test" >/dev/null; exitcode=$$?; if [ $$exitcode != 0 ]; then echo "$${test} failed" 1>&2; break; fi; done; exit $$exitcode
else
ifeq "$(V)" "1"
	$(Q)for test in $(basename $(UNITTEST_LIST)); do echo "$${test}:"; echo $(TEST_ENV) $(EXE_LAUNCHER) "$(BUILD_TOP)/tests/$$test"; $(TEST_ENV) $(EXE_LAUNCHER) "$(BUILD_TOP)/tests/$$test"; exitcode=$$?; if [ $$exitcode != 0 ]; then break; fi; echo "$${test} succeeded"; echo; done; if [ "$$exitcode" = 0 ]; then echo 'all subtests succeeded.'; else exit $$exitcode; fi
else
	$(Q)for test in $(basename $(UNITTEST_LIST)); do echo -n "$${test}..."; $(TEST_ENV) $(EXE_LAUNCHER) "$(BUILD_TOP)/tests/$$test" >/dev/null; exitcode=$$?; if [ $$exitcode != 0 ]; then break; fi; echo ' succeeded'; done; if [ "$$exitcode" = 0 ]; then echo 'all subtests succeeded.'; else exit $$exitcode; fi
endif
endif
ifdef BUILD_DYNAMIC
	$(Q)for test in $(UNITTEST_LIST_SHARED); do LD_LIBRARY_PATH=$(BUILD_TOP) $(TEST_ENV) $(EXE_LAUNCHER) "$(BUILD_TOP)/tests/$$test" >/dev/null || exit $?; done
ifndef VERY_QUIET
	$(Q)echo '$(UNITTEST_LIST_SHARED) succeeded.'
endif
endif
	$(Q)touch $(BUILD_TOP)/.tested

.PHONY: retest
retest:
	$(Q)$(RM) -f $(BUILD_TOP)/.tested
	$(Q)$(MAKE) -f $(THIS_MAKEFILE) test

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
	$(Q)mkdir -p $(INSTALL_LIBDIR)
	install -p -m 0644 $(INSTALL_LIBS) $(INSTALL_LIBDIR)
	$(Q)mkdir -p $(INSTALL_INCDIR)/wolfsentry
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
    VERSION := $(shell cd "$(SRC_TOP)" && git rev-parse --short=8 HEAD 2>/dev/null || echo xxxxxxxx)
    VERSION := $(VERSION)$(shell cd "$(SRC_TOP)" && git diff --quiet 2>/dev/null || [ $$? -ne 1 ] || echo "-dirty")
endif

ifndef RELEASE
    RELEASE := $(shell cd "$(SRC_TOP)" && git describe --tags "$$(git rev-list --tags='v[0-9]*' --max-count=1 2>/dev/null)" 2>/dev/null)
endif

.PHONY: dist
dist:
	$(Q)if [[ ! -d "$(SRC_TOP)/.git" ]]; then echo 'dist target requires git artifacts.' 1>&2; exit 1; fi
ifndef VERY_QUIET
	$(Q)echo "generating dist archive wolfsentry-$(VERSION).tgz"
endif
	$(Q)DEST_DIR="$$PWD"; \
	cd $(SRC_TOP); \
	if [[ "$(VERSION)" =~ -dirty$$ ]]; then \
		if [[ -n "$$(git ls-files -d)" ]]; then \
			echo '$@: error: there are uncommitted deletions of tracked files.' 1>&2; \
			false; \
		else \
			$(TAR) --transform 's~^~wolfsentry-$(VERSION)/~' --gzip -cf "$${DEST_DIR}/wolfsentry-$(VERSION).tgz" $$(git ls-files); \
		fi; \
	else \
		git archive --format=tgz --prefix="wolfsentry-$(VERSION)/" --worktree-attributes --output="$${DEST_DIR}/wolfsentry-$(VERSION).tgz" "$(VERSION)"; \
	fi

dist-test: dist
	$(Q)rm -rf $(BUILD_TOP)/dist-test
	$(Q)mkdir -p $(BUILD_TOP)/dist-test
ifdef VERY_QUIET
	$(Q)DEST_DIR="$$PWD" && cd $(BUILD_TOP)/dist-test && $(TAR) -xf "$${DEST_DIR}/wolfsentry-$(VERSION).tgz" && cd wolfsentry-$(VERSION) && $(MAKE) --quiet test
else
	$(Q)DEST_DIR="$$PWD" && cd $(BUILD_TOP)/dist-test && $(TAR) -xf "$${DEST_DIR}/wolfsentry-$(VERSION).tgz" && cd wolfsentry-$(VERSION) && $(MAKE) test
endif

dist-test-clean:
	$(Q)DEST_DIR="$$PWD" && [ -d $(BUILD_TOP)/dist-test/wolfsentry-$(VERSION) ] && [ -f $${DEST_DIR}/wolfsentry-$(VERSION).tgz ] && cd $(BUILD_TOP)/dist-test && $(TAR) -tf $${DEST_DIR}/wolfsentry-$(VERSION).tgz | grep -E -v '/$$' | xargs $(RM) -f
	$(Q)[ -d $(BUILD_TOP)/dist-test/wolfsentry-$(VERSION) ] && $(MAKE) $(EXTRA_MAKE_FLAGS) -f $(THIS_MAKEFILE) BUILD_TOP=$(BUILD_TOP)/dist-test/wolfsentry-$(VERSION) clean && rmdir $(BUILD_TOP)/dist-test

CLEAN_RM_ARGS = -f $(BUILD_TOP)/.build_params $(BUILD_TOP)/wolfsentry/wolfsentry_options.h $(BUILD_TOP)/.tested $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.o)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.So)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.d)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.Sd)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.gcno)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.gcda)) $(BUILD_TOP)/$(LIB_NAME) $(BUILD_TOP)/$(DYNLIB_NAME) $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)) $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST_SHARED)) $(addprefix $(BUILD_TOP)/tests/,$(addsuffix .d,$(UNITTEST_LIST))) $(addprefix $(BUILD_TOP)/tests/,$(addsuffix .d,$(UNITTEST_LIST_SHARED))) $(ANALYZER_BUILD_ARTIFACTS)

DOXYGEN_PREDEFINED := WOLFSENTRY_THREADSAFE WOLFSENTRY_PROTOCOL_NAMES WOLFSENTRY_HAVE_JSON_DOM WOLFSENTRY_ERROR_STRINGS LWIP_PACKET_FILTER_API NETXDUO_PACKET_FILTER_API __GNUC__=4 WOLFSENTRY_HAVE_GNU_ATOMICS WOLFSENTRY_NO_INLINE WOLFSENTRY_FOR_DOXYGEN attr_align_to(x)=
DOXYGEN_EXPAND_AS_DEFINED := WOLFSENTRY_SOCKADDR_MEMBERS WOLFSENTRY_FLEXIBLE_ARRAY_SIZE attr_align_to
DOXYGEN_EXCLUDE := wolfsentry/wolfsentry_options.h

PRINT_VERSION_RECIPE = cd '$(SRC_TOP)' && echo -e '\#include <stdio.h>\n\#include <stdlib.h>\n\#include <wolfsentry/wolfsentry.h>\nint main(int argc, char **argv) {\n(void)argc; (void)argv; printf("v%d.%d.%d\\n",WOLFSENTRY_VERSION_MAJOR,WOLFSENTRY_VERSION_MINOR,WOLFSENTRY_VERSION_TINY); exit(0);\n}' | $(CC) $(CFLAGS) -DBUILDING_LIBWOLFSENTRY $(LDFLAGS) -x c - -o '$(BUILD_TOP)/print_version.'$$$$ && '$(BUILD_TOP)/print_version.'$$$$ && rm -f '$(BUILD_TOP)/print_version.'$$$$

README_FOR_FULL_MANUAL_RECIPE = grep -v -E -e 'doc/[-_[:alnum:]]+\.md|ChangeLog\.md' '$(SRC_TOP)/README.md'

.PHONY: doc-html
doc-html:
	$(Q)command -v doxygen >/dev/null || doxygen
	$(Q)mkdir -p '$(BUILD_TOP)/doc' && \
	RELEASE_PER_HEADERS=$$($(PRINT_VERSION_RECIPE)) && \
	cd '$(BUILD_TOP)/doc' && \
	rm -rf html && \
	cp -Lrs $(SRC_TOP)/doc/doxy-formats/html . && \
	cd html && \
	cp -Lrs $(SRC_TOP)/wolfsentry . && \
	cp -Ls $(SRC_TOP)/ChangeLog.md $(SRC_TOP)/doc/*.md . && \
	$(README_FOR_FULL_MANUAL_RECIPE) > README.md && \
	{ [[ "$(VERY_QUIET)" = "1" ]] || echo 'Running doxygen...'; } && \
	DOXYGEN_PREDEFINED='$(DOXYGEN_PREDEFINED)' DOXYGEN_EXPAND_AS_DEFINED='$(DOXYGEN_EXPAND_AS_DEFINED)' DOXYGEN_EXCLUDE='$(DOXYGEN_EXCLUDE)' WOLFSENTRY_VERSION="$$RELEASE_PER_HEADERS" doxygen Doxyfile && \
	{ [[ -e doxygen_warnings ]]  || { echo '$(BUILD_TOP)/doc/html/doxygen_warnings not found.' 1>&2 && false; }; } && \
	{ [[ ! -s doxygen_warnings ]] || { echo '$(BUILD_TOP)/doc/html/doxygen_warnings has nonzero length.' 1>&2 && false; }; } && \
	{ [[ "$(VERY_QUIET)" = "1" ]] || echo 'HTML manual generated; top index is $(BUILD_TOP)/doc/html/html/index.html'; }

.PHONY: doc-html-clean
doc-html-clean:
	$(Q)rm -rf '$(BUILD_TOP)/doc/html'

$(BUILD_TOP)/doc/pdf/refman.pdf: $(addprefix $(SRC_TOP)/, $(filter-out %/wolfsentry_options.h,$(INSTALL_HEADERS)) ChangeLog.md README.md doc/freertos-lwip-app.md doc/json_configuration.md)
	$(Q)command -v doxygen >/dev/null || doxygen
	$(Q)command -v pdflatex >/dev/null || pdflatex
	$(Q)command -v makeindex >/dev/null || makeindex
	$(Q)mkdir -p '$(BUILD_TOP)/doc' && \
	RELEASE_PER_HEADERS=$$($(PRINT_VERSION_RECIPE)) && \
	cd '$(BUILD_TOP)/doc' && \
	rm -rf pdf && \
	cp -Lrs $(SRC_TOP)/doc/doxy-formats/pdf . && \
	cd pdf && \
	cp -Lrs $(SRC_TOP)/wolfsentry . && \
	cp -Ls $(SRC_TOP)/ChangeLog.md $(SRC_TOP)/doc/*.md . && \
	$(README_FOR_FULL_MANUAL_RECIPE) > README.md && \
	{ [[ "$(VERY_QUIET)" = "1" ]] || echo 'Running doxygen...'; } && \
	DOXYGEN_PREDEFINED='$(DOXYGEN_PREDEFINED)' DOXYGEN_EXPAND_AS_DEFINED='$(DOXYGEN_EXPAND_AS_DEFINED)' DOXYGEN_EXCLUDE='$(DOXYGEN_EXCLUDE)' WOLFSENTRY_VERSION="$$RELEASE_PER_HEADERS" doxygen Doxyfile && \
	{ [[ -e doxygen_warnings ]]  || { echo '$(BUILD_TOP)/doc/pdf/doxygen_warnings not found.' 1>&2 && false; }; } && \
	{ [[ ! -s doxygen_warnings ]] || { echo '$(BUILD_TOP)/doc/pdf/doxygen_warnings has nonzero length.' 1>&2 && false; }; } && \
	cd latex && \
	if [[ "$(V)" == "1" ]]; then make; elif [[ "$(VERY_QUIET)" = "1" ]]; then make --quiet MKIDX_CMD='makeindex -q' >/dev/null; else make --quiet; fi && \
	mv refman.pdf .. && \
	cd .. && \
	rm -rf latex && \
	{ [[ "$(VERY_QUIET)" = "1" ]] || echo 'PDF manual generated; moved to $(BUILD_TOP)/doc/pdf/refman.pdf'; }

doc-pdf: $(BUILD_TOP)/doc/pdf/refman.pdf

.PHONY: doc-pdf-clean
doc-pdf-clean:
	$(Q)rm -rf '$(BUILD_TOP)/doc/pdf'

doc: doc-html $(BUILD_TOP)/doc/pdf/refman.pdf

doc-clean: doc-html-clean doc-pdf-clean

.PHONY: clean
clean:
	$(Q)rm $(CLEAN_RM_ARGS)
	$(Q)rm -rf $(addsuffix .dSYM,$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST) $(UNITTEST_LIST_SHARED)))
	$(Q)[[ -d "$(BUILD_TOP)/wolfsentry" && ! "$(BUILD_TOP)" -ef "$(SRC_TOP)" ]] && find $(BUILD_TOP)/{src,tests,ports,lwip,wolfsentry,examples,scripts,FreeRTOS,.github,doc} -depth -type d -print0 2>/dev/null | xargs -0 rmdir && rmdir "${BUILD_TOP}" || exit 0
ifndef VERY_QUIET
	$(Q)echo 'cleaned all targets and ephemera in $(BUILD_TOP)'
endif

-include $(SRC_TOP)/Makefile.analyzers
-include $(SRC_TOP)/Makefile.maintenance
-include $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.d))
-include $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.Sd))
