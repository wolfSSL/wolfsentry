# Makefile
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

SHELL := /bin/bash

ifeq "$(V)" "1"
    override undefine VERY_QUIET
endif

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))

ifdef USER_MAKE_CONF
    include $(USER_MAKE_CONF)
endif

SRCS := wolfsentry_util.c wolfsentry_internal.c addr_families.c routes.c events.c actions.c kv.c action_builtins.c

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

CC_V := $(shell $(CC) -v 2>&1 | sed "s/'/'\\\\''/g")

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

AS_VERSION := $(shell $(AS) --version 2>&1 | sed "s/'/'\\\\''/g")
LD_VERSION := $(shell $(LD) --version 2>&1 | sed "s/'/'\\\\''/g")
AR_VERSION := $(shell $(AR) --version 2>&1 | sed "s/'/'\\\\''/g")

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

ifdef NO_STDIO
    CFLAGS += -DWOLFSENTRY_NO_STDIO
    NO_JSON := 1
endif

# JSON settings need to be extracted from $(USER_SETTINGS_FILE) to determine if JSON sources should be built.
ifdef USER_SETTINGS_FILE
    ifeq ($(shell grep -q -E -e '^#define WOLFSENTRY_NO_JSON$$' "$(USER_SETTINGS_FILE)" && echo 1 || echo 0), 1)
        USER_SETTINGS_NO_JSON := 1
    endif
    ifeq ($(shell grep -q -E -e '^#define WOLFSENTRY_NO_JSON_DOM$$' "$(USER_SETTINGS_FILE)" && echo 1 || echo 0), 1)
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
    ifneq "$(RUNTIME)" "FreeRTOS-lwIP"
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
    CFLAGS += -ffunction-sections -fdata-sections
    LDFLAGS += -Wl,--gc-sections -Wl,--strip-all
endif

.PHONY: all

LIB_NAME := libwolfsentry.a

INSTALL_LIBS := $(BUILD_TOP)/$(LIB_NAME)

INSTALL_HEADERS := wolfsentry/wolfsentry.h wolfsentry/wolfsentry_settings.h wolfsentry/wolfsentry_errcodes.h wolfsentry/wolfsentry_af.h wolfsentry/wolfsentry_util.h wolfsentry/wolfsentry_json.h wolfsentry/centijson_sax.h wolfsentry/centijson_dom.h wolfsentry/centijson_value.h

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
	@cd $(SRC_TOP) && [ -d .git ] || exit 0 && ([ -d .git/hooks ] || mkdir .git/hooks) && ([ -e .git/hooks/pre-push ] || ln -s ../../scripts/pre-push.sh .git/hooks/pre-push 2>/dev/null || exit 0)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
ifdef VERY_QUIET
	@{ $(BUILD_PARAMS) | cmp -s - $@; } 2>/dev/null; cmp_ev=$$?; if [ $$cmp_ev != 0 ]; then $(BUILD_PARAMS) > $@; fi; exit 0
else
	@{ $(BUILD_PARAMS) | cmp -s - $@; } 2>/dev/null; cmp_ev=$$?; if [ $$cmp_ev = 0 ]; then echo 'Build parameters unchanged.'; else $(BUILD_PARAMS) > $@; if [ $$cmp_ev = 1 ]; then echo 'Rebuilding with changed build parameters.'; else echo 'Building fresh.'; fi; fi; exit 0
endif

ifndef USER_SETTINGS_FILE
$(BUILD_TOP)/wolfsentry/wolfsentry_options.h: $(SRC_TOP)/scripts/build_wolfsentry_options_h.awk $(BUILD_TOP)/.build_params
	@[ -d $(BUILD_TOP)/wolfsentry ] || mkdir -p $(BUILD_TOP)/wolfsentry
	@echo '$(CFLAGS)' | $< > $@
endif

$(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.o)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.So)): $(BUILD_TOP)/.build_params $(OPTIONS_FILE) $(SRC_TOP)/Makefile

INTERNAL_CFLAGS := -DBUILDING_LIBWOLFSENTRY -MMD

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

UNITTEST_LIST := test_init test_rwlocks test_static_routes test_dynamic_rules test_user_values test_user_addr_families $(UNITTEST_LIST_EXTRAS)

ifneq "$(NO_JSON)" "1"
    UNITTEST_LIST += test_json
    ifndef NO_JSON_DOM
        UNITTEST_LIST += $(UNITTEST_LIST_JSON_DOM_EXTRAS)
        TEST_JSON_CFLAGS:=-DTEST_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/test-config.json\" -DEXTRA_TEST_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/extra-test-config.json\" -DTEST_NUMERIC_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/test-config-numeric.json\"
    else
        TEST_JSON_CFLAGS:=-DTEST_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/test-config-no-dom.json\" -DEXTRA_TEST_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/extra-test-config.json\" -DTEST_NUMERIC_JSON_CONFIG_PATH=\"$(SRC_TOP)/tests/test-config-numeric-no-dom.json\"
    endif
    $(BUILD_TOP)/tests/test_json: override CFLAGS+=$(TEST_JSON_CFLAGS)
endif

$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)): UNITTEST_GATE=-D$(shell basename '$@' | tr '[:lower:]' '[:upper:]')
$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)): $(SRC_TOP)/tests/unittests.c $(BUILD_TOP)/$(LIB_NAME) $(OPTIONS_FILE)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
ifeq "$(V)" "1"
	$(CC) $(CFLAGS) $(UNITTEST_GATE) $(LDFLAGS) -o $@ $(filter-out %.h,$^)
else
ifndef VERY_QUIET
	@echo "$(CC) ... -o $@"
endif
	@$(CC) $(CFLAGS) $(UNITTEST_GATE) $(LDFLAGS) -o $@ $(filter-out %.h,$^)
endif


UNITTEST_LIST_SHARED=test_all_shared
UNITTEST_SHARED_FLAGS := $(addprefix -D,$(shell echo '$(UNITTEST_LIST)' | tr '[:lower:]' '[:upper:]')) $(TEST_JSON_CFLAGS)

$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST_SHARED)): $(SRC_TOP)/tests/unittests.c $(BUILD_TOP)/$(DYNLIB_NAME) $(OPTIONS_FILE)
	@[ -d $(dir $@) ] || mkdir -p $(dir $@)
ifeq "$(V)" "1"
	$(CC) $(CFLAGS) $(UNITTEST_SHARED_FLAGS) $(LDFLAGS) -o $@ $< $(BUILD_TOP)/$(DYNLIB_NAME)
else
ifndef VERY_QUIET
	@echo "$(CC) ... -o $@"
endif
	@$(CC) $(CFLAGS) $(UNITTEST_SHARED_FLAGS) $(LDFLAGS) -o $@ $< $(BUILD_TOP)/$(DYNLIB_NAME)
endif

ifdef BUILD_DYNAMIC
$(BUILD_TOP)/.tested: $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST_SHARED))
endif


.PHONY: test
test: $(BUILD_TOP)/.tested

$(BUILD_TOP)/.tested: $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST))
ifdef VERY_QUIET
	@for test in $(basename $(UNITTEST_LIST)); do $(TEST_ENV) $(EXE_LAUNCHER) "$(BUILD_TOP)/tests/$$test" >/dev/null; exitcode=$$?; if [ $$exitcode != 0 ]; then echo "$${test} failed" 1>&2; break; fi; done; exit $$exitcode
else
ifeq "$(V)" "1"
	@for test in $(basename $(UNITTEST_LIST)); do echo "$${test}:"; echo $(TEST_ENV) $(EXE_LAUNCHER) "$(BUILD_TOP)/tests/$$test"; $(TEST_ENV) $(EXE_LAUNCHER) "$(BUILD_TOP)/tests/$$test"; exitcode=$$?; if [ $$exitcode != 0 ]; then break; fi; echo "$${test} succeeded"; echo; done; if [ "$$exitcode" = 0 ]; then echo 'all subtests succeeded.'; else exit $$exitcode; fi
else
	@for test in $(basename $(UNITTEST_LIST)); do echo -n "$${test}..."; $(TEST_ENV) $(EXE_LAUNCHER) "$(BUILD_TOP)/tests/$$test" >/dev/null; exitcode=$$?; if [ $$exitcode != 0 ]; then break; fi; echo ' succeeded'; done; if [ "$$exitcode" = 0 ]; then echo 'all subtests succeeded.'; else exit $$exitcode; fi
endif
endif
ifdef BUILD_DYNAMIC
	@for test in $(UNITTEST_LIST_SHARED); do LD_LIBRARY_PATH=$(BUILD_TOP) $(TEST_ENV) $(EXE_LAUNCHER) "$(BUILD_TOP)/tests/$$test" >/dev/null || exit $?; done
ifndef VERY_QUIET
	@echo '$(UNITTEST_LIST_SHARED) succeeded.'
endif
endif
	@touch $(BUILD_TOP)/.tested

.PHONY: retest
retest:
	@$(RM) -f $(BUILD_TOP)/.tested
	@$(MAKE) -f $(THIS_MAKEFILE) test

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
    VERSION := $(shell cd "$(SRC_TOP)" && git rev-parse --short=8 HEAD 2>/dev/null || echo xxxxxxxx)
    VERSION := $(VERSION)$(shell cd "$(SRC_TOP)" && git diff --quiet 2>/dev/null || [ $$? -ne 1 ] || echo "-dirty")
endif

ifndef RELEASE
    RELEASE := $(shell cd "$(SRC_TOP)" && git describe --tags "$$(git rev-list --tags='v[0-9]*' --max-count=1 2>/dev/null)" 2>/dev/null)
endif

.PHONY: dist
dist:
	@if [[ ! -d "$(SRC_TOP)/.git" ]]; then echo 'dist target requires git artifacts.' 1>&2; exit 1; fi
ifndef VERY_QUIET
	@echo "generating dist archive wolfsentry-$(VERSION).tgz"
endif
	@DEST_DIR="$$PWD"; \
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
	@rm -rf $(BUILD_TOP)/dist-test
	@mkdir -p $(BUILD_TOP)/dist-test
ifdef VERY_QUIET
	@DEST_DIR="$$PWD" && cd $(BUILD_TOP)/dist-test && $(TAR) -xf "$${DEST_DIR}/wolfsentry-$(VERSION).tgz" && cd wolfsentry-$(VERSION) && $(MAKE) --quiet test
else
	@DEST_DIR="$$PWD" && cd $(BUILD_TOP)/dist-test && $(TAR) -xf "$${DEST_DIR}/wolfsentry-$(VERSION).tgz" && cd wolfsentry-$(VERSION) && $(MAKE) test
endif

dist-test-clean:
	@DEST_DIR="$$PWD" && [ -d $(BUILD_TOP)/dist-test/wolfsentry-$(VERSION) ] && [ -f $${DEST_DIR}/wolfsentry-$(VERSION).tgz ] && cd $(BUILD_TOP)/dist-test && $(TAR) -tf $${DEST_DIR}/wolfsentry-$(VERSION).tgz | grep -E -v '/$$' | xargs $(RM) -f
	@[ -d $(BUILD_TOP)/dist-test/wolfsentry-$(VERSION) ] && $(MAKE) $(EXTRA_MAKE_FLAGS) -f $(THIS_MAKEFILE) BUILD_TOP=$(BUILD_TOP)/dist-test/wolfsentry-$(VERSION) clean && rmdir $(BUILD_TOP)/dist-test

CLEAN_RM_ARGS = -f $(BUILD_TOP)/.build_params $(BUILD_TOP)/wolfsentry/wolfsentry_options.h $(BUILD_TOP)/.tested $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.o)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.So)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.d)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.Sd)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.gcno)) $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.gcda)) $(BUILD_TOP)/$(LIB_NAME) $(BUILD_TOP)/$(DYNLIB_NAME) $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST)) $(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST_SHARED)) $(addprefix $(BUILD_TOP)/tests/,$(addsuffix .d,$(UNITTEST_LIST))) $(addprefix $(BUILD_TOP)/tests/,$(addsuffix .d,$(UNITTEST_LIST_SHARED))) $(ANALYZER_BUILD_ARTIFACTS)

.PHONY: release
release:
	@if [[ -z "$(RELEASE)" ]]; then echo "Can't make release -- version isn't known."; exit 1; fi
	@cd "$(SRC_TOP)" && git show "$(RELEASE):wolfsentry/wolfsentry.h" | awk '/^#define WOLFSENTRY_VERSION_MAJOR /{major=$$3; next;}/^#define WOLFSENTRY_VERSION_MINOR /{minor=$$3; next;}/^#define WOLFSENTRY_VERSION_TINY /{tiny=$$3; next;} {if ((major != "") && (minor != "") && (tiny != "")) {exit(0);}} END { if ("v" major "." minor "." tiny == "$(RELEASE)") {exit(0);} else {printf("make release: tagged version \"%s\" doesn'\''t match version in header \"v%s.%s.%s\".\n", "$(RELEASE)", major, minor, tiny) > "/dev/stderr"; exit(1);}; }'
	@REFMAN_UPDATED_AT=$$(git --no-pager log -n 1 --pretty=format:%at '$(RELEASE)' doc/wolfSentry_refman.pdf 2>/dev/null); if [[ -n "$$REFMAN_UPDATED_AT" && ($$(git --no-pager log -n 1 --pretty=format:%at '$(RELEASE)' wolfsentry/ doc/ ChangeLog.md README.md) -gt "$$REFMAN_UPDATED_AT") ]]; then echo -e 'error: tag "$(RELEASE)" has doc/wolfSentry_refman.pdf older than header(s) and/or documentation.\nfix with: make doc/wolfSentry_refman.pdf && git commit -n doc/wolfSentry_refman.pdf && git tag -f "$(RELEASE)"' 1>&2; false; fi
ifndef VERY_QUIET
	@echo "generating release archive $${PWD}/wolfsentry-$(RELEASE).zip"
endif
	@DEST_DIR="$$PWD"; \
	cd $(SRC_TOP) || exit $$?; \
	git archive --format=zip --prefix="wolfsentry-$(RELEASE)/" --worktree-attributes --output="$${DEST_DIR}/wolfsentry-$(RELEASE).zip" "$(RELEASE)"

.PHONY: com-bundle
com-bundle:
	@if [[ -z "$(RELEASE)" ]]; then echo "Can't make commercial bundle -- version isn't known."; exit 1; fi
ifndef VERY_QUIET
	@echo "generating com-bundle $${PWD}/wolfsentry-$(RELEASE)-commercial.7z ..."
endif
	@DEST_DIR="$$PWD"; \
	cd $(SRC_TOP) || exit $$?; \
	read -r -p 'com bundle password? [empty to autogenerate] ' the_password; \
	if [[ -z "$$the_password" ]]; then the_password=$$(head -c 15 /dev/urandom | base64) || exit $$?; echo "com-bundle generated password: $${the_password}"; fi; \
	workdir=$$(mktemp -d) || exit $$?; \
	trap "rm -rf \"$$workdir\"" EXIT; \
	git archive --format=tar --prefix="wolfsentry-$(RELEASE)-commercial/" --worktree-attributes "$(RELEASE)" | (cd "$$workdir" && tar -xf -) || exit $$?; \
	pushd "$$workdir" >/dev/null || exit $$?; \
	$(SRC_TOP)/scripts/convert_copyright_boilerplate.awk $$(find . -name Makefile\* -o -name '*.[ch]' -o -name '*.sh' -o -name '*.awk') || exit $$?; \
	if [[ -e "$${DEST_DIR}/wolfsentry-$(RELEASE)-commercial.7z" ]]; then rm "$${DEST_DIR}/wolfsentry-$(RELEASE)-commercial.7z" || exit $$?; fi; \
	7za a -r -mmt -mhe=on -mx=9 -ms=on -p"$$the_password" "$${DEST_DIR}/wolfsentry-$(RELEASE)-commercial.7z" "wolfsentry-$(RELEASE)-commercial" 1>/dev/null || exit $$?; \
	echo -n "com-bundle SHA256: " && sha256sum "$${DEST_DIR}/wolfsentry-$(RELEASE)-commercial.7z"

DOXYGEN_PREDEFINED := WOLFSENTRY_THREADSAFE WOLFSENTRY_PROTOCOL_NAMES WOLFSENTRY_HAVE_JSON_DOM WOLFSENTRY_ERROR_STRINGS LWIP_PACKET_FILTER_API __GNUC__=4 WOLFSENTRY_HAVE_GNU_ATOMICS WOLFSENTRY_NO_INLINE WOLFSENTRY_FOR_DOXYGEN attr_align_to(x)=
DOXYGEN_EXPAND_AS_DEFINED := WOLFSENTRY_SOCKADDR_MEMBERS WOLFSENTRY_FLEXIBLE_ARRAY_SIZE attr_align_to
DOXYGEN_EXCLUDE := wolfsentry/wolfsentry_options.h

PRINT_VERSION_RECIPE = cd '$(SRC_TOP)' && echo -e '\#include <stdio.h>\n\#include <stdlib.h>\n\#include <wolfsentry/wolfsentry.h>\nint main(int argc, char **argv) {\n(void)argc; (void)argv; printf("v%d.%d.%d\\n",WOLFSENTRY_VERSION_MAJOR,WOLFSENTRY_VERSION_MINOR,WOLFSENTRY_VERSION_TINY); exit(0);\n}' | $(CC) $(CFLAGS) -DBUILDING_LIBWOLFSENTRY $(LDFLAGS) -x c - -o '$(BUILD_TOP)/print_version.$$$$' && '$(BUILD_TOP)/print_version.$$$$' && rm -f '$(BUILD_TOP)/print_version.$$$$'

.PHONY: doc-html
doc-html:
	@command -v doxygen >/dev/null || doxygen
	@mkdir -p '$(BUILD_TOP)/doc' && \
	RELEASE_PER_HEADERS=$$($(PRINT_VERSION_RECIPE)) && \
	cd '$(BUILD_TOP)/doc' && \
	rm -rf html && \
	cp -rs $(SRC_TOP)/doc/doxy-formats/html . && \
	cd html && \
	cp -rs $(SRC_TOP)/wolfsentry . && \
	cp -s $(SRC_TOP)/ChangeLog.md $(SRC_TOP)/doc/*.md . && \
	grep -v -F -e '<!-- not-for-full-manuals -->' '$(SRC_TOP)/README.md' > README.md && \
	{ [[ "$(VERY_QUIET)" = "1" ]] || echo 'Running doxygen...'; } && \
	DOXYGEN_PREDEFINED='$(DOXYGEN_PREDEFINED)' DOXYGEN_EXPAND_AS_DEFINED='$(DOXYGEN_EXPAND_AS_DEFINED)' DOXYGEN_EXCLUDE='$(DOXYGEN_EXCLUDE)' WOLFSENTRY_VERSION="$$RELEASE_PER_HEADERS" doxygen Doxyfile && \
	{ [[ -e doxygen_warnings ]]  || { echo '$(BUILD_TOP)/doc/html/doxygen_warnings not found.' 1>&2 && false; }; } && \
	{ [[ ! -s doxygen_warnings ]] || { echo '$(BUILD_TOP)/doc/html/doxygen_warnings has nonzero length.' 1>&2 && false; }; } && \
	{ [[ "$(VERY_QUIET)" = "1" ]] || echo 'HTML manual generated; top index is $(BUILD_TOP)/doc/html/html/index.html'; }

.PHONY: doc-html-clean
doc-html-clean:
	@rm -rf '$(BUILD_TOP)/doc/html'

$(BUILD_TOP)/doc/pdf/refman.pdf: $(addprefix $(SRC_TOP)/, $(filter-out %/wolfsentry_options.h,$(INSTALL_HEADERS)) ChangeLog.md README.md doc/freertos-lwip-app.md doc/json_configuration.md)
	@command -v doxygen >/dev/null || doxygen
	@command -v pdflatex >/dev/null || pdflatex
	@command -v makeindex >/dev/null || makeindex
	@mkdir -p '$(BUILD_TOP)/doc' && \
	RELEASE_PER_HEADERS=$$($(PRINT_VERSION_RECIPE)) && \
	cd '$(BUILD_TOP)/doc' && \
	rm -rf pdf && \
	cp -rs $(SRC_TOP)/doc/doxy-formats/pdf . && \
	cd pdf && \
	cp -rs $(SRC_TOP)/wolfsentry . && \
	cp -s $(SRC_TOP)/ChangeLog.md $(SRC_TOP)/doc/*.md . && \
	grep -v -F -e '<!-- not-for-full-manuals -->' '$(SRC_TOP)/README.md' > README.md && \
	echo 'Running doxygen...' && \
	DOXYGEN_PREDEFINED='$(DOXYGEN_PREDEFINED)' DOXYGEN_EXPAND_AS_DEFINED='$(DOXYGEN_EXPAND_AS_DEFINED)' DOXYGEN_EXCLUDE='$(DOXYGEN_EXCLUDE)' WOLFSENTRY_VERSION="$$RELEASE_PER_HEADERS" doxygen Doxyfile && \
	{ [[ -e doxygen_warnings ]]  || { echo '$(BUILD_TOP)/doc/pdf/doxygen_warnings not found.' 1>&2 && false; }; } && \
	{ [[ ! -s doxygen_warnings ]] || { echo '$(BUILD_TOP)/doc/pdf/doxygen_warnings has nonzero length.' 1>&2 && false; }; } && \
	cd latex && \
	make --quiet && \
	mv refman.pdf .. && \
	cd .. && \
	rm -rf latex && \
	echo 'PDF manual generated; moved to $(BUILD_TOP)/doc/pdf/refman.pdf'

doc-pdf: $(BUILD_TOP)/doc/pdf/refman.pdf

.PHONY: doc-pdf-clean
doc-pdf-clean:
	@rm -rf '$(BUILD_TOP)/doc/pdf'

doc: doc-html $(BUILD_TOP)/doc/pdf/refman.pdf

doc-clean: doc-html-clean doc-pdf-clean

doc/wolfSentry_refman.pdf: $(SRC_TOP)/doc/wolfSentry_refman.pdf
$(SRC_TOP)/doc/wolfSentry_refman.pdf: $(BUILD_TOP)/doc/pdf/refman.pdf
	@cp -p "$(BUILD_TOP)/doc/pdf/refman.pdf" "$@"
	@echo 'updated $@'

DOC_SYNC_BASE_BRANCH := master

.PHONY: doc-sync
doc-sync: $(SRC_TOP)/doc/wolfSentry_refman.pdf
	@cd $(SRC_TOP)/../documentation || exit $$?; \
	if [[ -n '$(DOC_SYNC_NEW_BRANCH)' ]]; then \
	    NEW_BRANCH='$(DOC_SYNC_NEW_BRANCH)'; \
	    git checkout "$${NEW_BRANCH}" || exit $$?; \
	else \
	    NEW_BRANCH=$$(date +%Y%m%d)-wolfsentry-doc-sync; \
	    [[ "$$NEW_BRANCH" != '$(DOC_SYNC_BASE_BRANCH)' ]] || { echo 'supplied DOC_SYNC_BASE_BRANCH collides with constructed branch name.' 1>&2; exit 1; }; \
	    git checkout -b "$${NEW_BRANCH}" '$(DOC_SYNC_BASE_BRANCH)' || exit $$?; \
	fi; \
	cd wolfSentry/src && \
	git ls-files --error-unmatch README.md freertos-lwip-app.md json_configuration.md ChangeLog.md >/dev/null && \
	grep -v -F -e '<!-- not-for-full-manuals -->' '$(SRC_TOP)/README.md' >| README.md && \
	cp -p $(SRC_TOP)/doc/freertos-lwip-app.md $(SRC_TOP)/doc/json_configuration.md $(SRC_TOP)/ChangeLog.md . && \
	git commit -n -a && \
	git push --no-verify origin "$$NEW_BRANCH"; \
	exitval=$$?; \
	if [[ $$exitval != 0 ]]; then \
	    git reset -q --hard; \
	    if [[ -z '$(DOC_SYNC_NEW_BRANCH)' ]]; then \
	        git checkout DOC_SYNC_BASE_BRANCH && git branch -D "$$NEW_BRANCH"; \
	    fi; \
	fi; \
	exit $$exitval

.PHONY: clean
clean:
ifeq "$(V)" "1"
	rm $(CLEAN_RM_ARGS)
else
	@rm $(CLEAN_RM_ARGS)
endif
	@rm -rf $(addsuffix .dSYM,$(addprefix $(BUILD_TOP)/tests/,$(UNITTEST_LIST) $(UNITTEST_LIST_SHARED)))
	@[[ -d "$(BUILD_TOP)/wolfsentry" && ! "$(BUILD_TOP)" -ef "$(SRC_TOP)" ]] && find $(BUILD_TOP)/{src,tests,ports,lwip,wolfsentry,examples,scripts,FreeRTOS,.github,doc} -depth -type d -print0 2>/dev/null | xargs -0 rmdir && rmdir "${BUILD_TOP}" || exit 0
ifndef VERY_QUIET
	@echo 'cleaned all targets and ephemera in $(BUILD_TOP)'
endif

-include $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.d))
-include $(addprefix $(BUILD_TOP)/src/,$(SRCS:.c=.Sd))
