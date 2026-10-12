TOOLPREFIX ?= arm-none-eabi-
CC := $(TOOLPREFIX)gcc
AR := $(TOOLPREFIX)ar
RANLIB := $(TOOLPREFIX)ranlib
OBJCOPY := $(TOOLPREFIX)objcopy
SIZE := $(TOOLPREFIX)size

ROOT := ../..
BUILD_DIR ?= build
FREERTOS_TOP ?= $(ROOT)/../freertos
FREERTOS_KERNEL := $(FREERTOS_TOP)/FreeRTOS/Source
LWIP_TOP ?= $(ROOT)/../lwip
WOLFSSL_TOP ?= $(ROOT)/../wolfssl
M33MU ?= m33mu

FREERTOS_PORT := portable/GCC/ARM_CM33_NTZ/non_secure
INCLUDE_DIR := $(CURDIR)/include
WOLFSENTRY_BUILD := $(abspath $(BUILD_DIR)/wolfsentry)
CPU_FLAGS := -mcpu=cortex-m33 -mthumb -mno-unaligned-access
COMMON_FLAGS := $(CPU_FLAGS) -Os -g -ffunction-sections -fdata-sections \
    -fno-common -Wall -Wextra -Werror=format \
    -DFREERTOS -DWOLFSENTRY_LWIP -DWOLFSENTRY_NO_GETPROTOBY \
    -DWOLFSENTRY_NO_POSIX_MEMALIGN \
    -I$(INCLUDE_DIR) -I$(ROOT) -I$(WOLFSENTRY_BUILD) \
    -I$(FREERTOS_KERNEL)/include -I$(FREERTOS_KERNEL)/$(FREERTOS_PORT) \
    -I$(LWIP_TOP)/src/include \
    -I$(LWIP_TOP)/contrib/ports/freertos/include
C89_FLAGS := -std=c89 -pedantic -DWOLFSENTRY_C89 -D_ISOC99_SOURCE \
    -Wno-long-long -Wno-overlength-strings -Wno-variadic-macros
TLS_C89_FLAGS := -std=gnu89 -DWOLFSENTRY_C89 -D_ISOC99_SOURCE \
    -Wno-long-long -Wno-overlength-strings -Wno-variadic-macros
THIRD_PARTY_FLAGS := -std=gnu11 -Wno-unused-parameter -Wno-sign-conversion \
    -Wno-conversion -Wno-cast-align
WOLFSSL_CFLAGS := $(CPU_FLAGS) -Os -ffunction-sections -fdata-sections \
    -I$(INCLUDE_DIR) -I$(FREERTOS_KERNEL)/include \
    -I$(FREERTOS_KERNEL)/$(FREERTOS_PORT) -I$(LWIP_TOP)/src/include
LINK_FLAGS = $(CPU_FLAGS) -specs=nano.specs -specs=nosys.specs \
    -Wl,-T,linker.ld -Wl,--gc-sections -Wl,-Map,$@.map

FREERTOS_SRCS := \
    $(FREERTOS_KERNEL)/tasks.c \
    $(FREERTOS_KERNEL)/list.c \
    $(FREERTOS_KERNEL)/queue.c \
    $(FREERTOS_KERNEL)/portable/MemMang/heap_4.c \
    $(FREERTOS_KERNEL)/$(FREERTOS_PORT)/port.c \
    $(FREERTOS_KERNEL)/$(FREERTOS_PORT)/portasm.c

LWIP_SRCS := \
    $(LWIP_TOP)/src/core/def.c \
    $(LWIP_TOP)/src/core/init.c \
    $(LWIP_TOP)/src/core/inet_chksum.c \
    $(LWIP_TOP)/src/core/ip.c \
    $(LWIP_TOP)/src/core/mem.c \
    $(LWIP_TOP)/src/core/memp.c \
    $(LWIP_TOP)/src/core/netif.c \
    $(LWIP_TOP)/src/core/pbuf.c \
    $(LWIP_TOP)/src/core/raw.c \
    $(LWIP_TOP)/src/core/stats.c \
    $(LWIP_TOP)/src/core/sys.c \
    $(LWIP_TOP)/src/core/tcp.c \
    $(LWIP_TOP)/src/core/tcp_in.c \
    $(LWIP_TOP)/src/core/tcp_out.c \
    $(LWIP_TOP)/src/core/timeouts.c \
    $(LWIP_TOP)/src/core/udp.c \
    $(LWIP_TOP)/src/core/ipv4/etharp.c \
    $(LWIP_TOP)/src/core/ipv4/icmp.c \
    $(LWIP_TOP)/src/core/ipv4/ip4.c \
    $(LWIP_TOP)/src/core/ipv4/ip4_addr.c \
    $(LWIP_TOP)/src/core/ipv4/ip4_frag.c \
    $(LWIP_TOP)/src/api/api_lib.c \
    $(LWIP_TOP)/src/api/api_msg.c \
    $(LWIP_TOP)/src/api/err.c \
    $(LWIP_TOP)/src/api/netbuf.c \
    $(LWIP_TOP)/src/api/sockets.c \
    $(LWIP_TOP)/src/api/tcpip.c \
    $(LWIP_TOP)/src/netif/ethernet.c \
    $(LWIP_TOP)/contrib/ports/freertos/sys_arch.c

PLATFORM_SRCS := startup.c
BASIC_SRCS := $(ROOT)/examples/STM32-LWIP/Src/sentry.c \
    $(ROOT)/examples/STM32-LWIP/Src/echo.c \
    $(ROOT)/examples/STM32-LWIP/Src/ping.c
TLS_SRCS := $(ROOT)/examples/STM32-LWIP-WOLFSSL/Src/sentry.c \
    $(ROOT)/examples/STM32-LWIP-WOLFSSL/Src/echo.c

PLATFORM_OBJS := $(patsubst %.c,$(BUILD_DIR)/common/%.o,$(PLATFORM_SRCS))
FREERTOS_OBJS := $(patsubst $(FREERTOS_KERNEL)/%.c,$(BUILD_DIR)/freertos/%.o,$(FREERTOS_SRCS))
LWIP_OBJS := $(patsubst $(LWIP_TOP)/%.c,$(BUILD_DIR)/lwip/%.o,$(LWIP_SRCS))
COMMON_OBJS := $(PLATFORM_OBJS) $(FREERTOS_OBJS) $(LWIP_OBJS)
BASIC_OBJS := $(patsubst %.c,$(BUILD_DIR)/basic/%.o,$(notdir $(BASIC_SRCS)))
TLS_OBJS := $(patsubst %.c,$(BUILD_DIR)/tls/%.o,$(notdir $(TLS_SRCS)))

.PHONY: all clean run check-paths wolfsentry wolfssl

all: $(BUILD_DIR)/stm32-lwip.bin $(BUILD_DIR)/stm32-lwip-wolfssl.bin

check-paths:
	@test -f $(FREERTOS_KERNEL)/tasks.c || { echo "FREERTOS_TOP is invalid" >&2; exit 1; }
	@test -f $(LWIP_TOP)/src/core/init.c || { echo "LWIP_TOP is invalid" >&2; exit 1; }
	@test -f $(LWIP_TOP)/contrib/ports/freertos/sys_arch.c || { echo "lwIP contrib is required" >&2; exit 1; }

wolfsentry: check-paths
	$(MAKE) -C $(ROOT) -j2 \
	    BUILD_TOP=$(WOLFSENTRY_BUILD) \
	    HOST=arm-none-eabi RUNTIME=FreeRTOS-lwIP \
	    FREERTOS_TOP=$(abspath $(FREERTOS_TOP)) \
	    FREERTOS_PORT=ARM_CM33_NTZ/non_secure \
	    RUNTIME_INCLUDE_DIR=$(INCLUDE_DIR) \
	    LWIP_TOP=$(abspath $(LWIP_TOP)) \
	    EXTRA_CFLAGS='$(CPU_FLAGS) $(C89_FLAGS) -I$(abspath $(LWIP_TOP))/contrib/ports/freertos/include' \
	    FUNCTION_SECTIONS=1

$(WOLFSENTRY_BUILD)/libwolfsentry.a: wolfsentry
	@test -f $@

wolfssl: $(WOLFSSL_TOP)/src/.libs/libwolfssl.a

$(WOLFSSL_TOP)/src/.libs/libwolfssl.a:
	@test -x $(WOLFSSL_TOP)/autogen.sh || { echo "WOLFSSL_TOP is invalid" >&2; exit 1; }
	@test -f $(FREERTOS_KERNEL)/tasks.c || { echo "FREERTOS_TOP is invalid" >&2; exit 1; }
	@test -f $(LWIP_TOP)/src/core/init.c || { echo "LWIP_TOP is invalid" >&2; exit 1; }
	cd $(WOLFSSL_TOP) && ./autogen.sh
	cd $(WOLFSSL_TOP) && \
	    CC=$(CC) AR=$(AR) RANLIB=$(RANLIB) \
	    CFLAGS='$(WOLFSSL_CFLAGS)' \
	    LDFLAGS='$(CPU_FLAGS) -specs=nosys.specs' \
	    ./configure --host=arm-none-eabi --enable-usersettings \
	        --enable-static --disable-shared --disable-examples \
	        --disable-crypttests --disable-benchmark --disable-filesystem
	$(MAKE) -C $(WOLFSSL_TOP) -j2 \
	    EXTRA_CFLAGS='-Wno-error=unused-parameter -Wno-error=bad-function-cast' \
	    src/libwolfssl.la

$(BUILD_DIR)/common/%.o: %.c | check-paths
	@mkdir -p $(@D)
	$(CC) $(COMMON_FLAGS) $(C89_FLAGS) -c $< -o $@

$(BUILD_DIR)/freertos/%.o: $(FREERTOS_KERNEL)/%.c | check-paths
	@mkdir -p $(@D)
	$(CC) $(COMMON_FLAGS) $(THIRD_PARTY_FLAGS) -c $< -o $@

$(BUILD_DIR)/lwip/%.o: $(LWIP_TOP)/%.c | check-paths
	@mkdir -p $(@D)
	$(CC) $(COMMON_FLAGS) $(THIRD_PARTY_FLAGS) -c $< -o $@

$(BUILD_DIR)/basic/main.o: main.c | check-paths
	@mkdir -p $(@D)
	$(CC) $(COMMON_FLAGS) $(C89_FLAGS) -DECHO_DEBUG=LWIP_DBG_OFF \
	    -I$(ROOT)/examples/STM32-LWIP/Inc \
	    -c $< -o $@

$(BUILD_DIR)/tls/main.o: main.c | check-paths
	@mkdir -p $(@D)
	$(CC) $(COMMON_FLAGS) $(TLS_C89_FLAGS) -DM33MU_EXAMPLE_TLS \
	    -DWOLFSSL_USER_SETTINGS -I$(ROOT)/examples/STM32-LWIP-WOLFSSL/Inc \
	    -I$(WOLFSSL_TOP) -c $< -o $@

$(BUILD_DIR)/basic/%.o: $(ROOT)/examples/STM32-LWIP/Src/%.c | check-paths
	@mkdir -p $(@D)
	$(CC) $(COMMON_FLAGS) $(C89_FLAGS) -DECHO_DEBUG=LWIP_DBG_OFF \
	    -I$(ROOT)/examples/STM32-LWIP/Inc \
	    -c $< -o $@

$(BUILD_DIR)/tls/%.o: $(ROOT)/examples/STM32-LWIP-WOLFSSL/Src/%.c | check-paths
	@mkdir -p $(@D)
	$(CC) $(COMMON_FLAGS) $(TLS_C89_FLAGS) -DM33MU_EXAMPLE_TLS \
	    -DWOLFSSL_USER_SETTINGS -I$(ROOT)/examples/STM32-LWIP-WOLFSSL/Inc \
	    -I$(WOLFSSL_TOP) -c $< -o $@

$(BUILD_DIR)/stm32-lwip.elf: $(COMMON_OBJS) $(BUILD_DIR)/basic/main.o $(BASIC_OBJS) \
    $(WOLFSENTRY_BUILD)/libwolfsentry.a linker.ld
	$(CC) $(LINK_FLAGS) -o $@ $(COMMON_OBJS) $(BUILD_DIR)/basic/main.o $(BASIC_OBJS) \
	    $(WOLFSENTRY_BUILD)/libwolfsentry.a -lc -lm -lgcc
	$(SIZE) $@

$(BUILD_DIR)/stm32-lwip-wolfssl.elf: $(COMMON_OBJS) $(BUILD_DIR)/tls/main.o $(TLS_OBJS) \
    $(WOLFSENTRY_BUILD)/libwolfsentry.a $(WOLFSSL_TOP)/src/.libs/libwolfssl.a \
    linker.ld
	$(CC) $(LINK_FLAGS) -o $@ $(COMMON_OBJS) $(BUILD_DIR)/tls/main.o $(TLS_OBJS) \
	    $(WOLFSENTRY_BUILD)/libwolfsentry.a \
	    $(WOLFSSL_TOP)/src/.libs/libwolfssl.a -lc -lm -lgcc
	$(SIZE) $@

$(BUILD_DIR)/%.bin: $(BUILD_DIR)/%.elf
	$(OBJCOPY) -O binary $< $@

run: all
	M33MU=$(M33MU) ./run.sh $(BUILD_DIR)/stm32-lwip.bin \
	    'PASS: STM32-LWIP on FreeRTOS/lwIP under M33MU'
	M33MU=$(M33MU) ./run.sh $(BUILD_DIR)/stm32-lwip-wolfssl.bin \
	    'PASS: STM32-LWIP-WOLFSSL on FreeRTOS/lwIP under M33MU'

clean:
	rm -rf $(BUILD_DIR)
