/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;
extern uint32_t _estack;
extern unsigned char _heap_start;
extern unsigned char _heap_end;

extern int main(void);
extern void SVC_Handler(void);
extern void PendSV_Handler(void);
extern void SysTick_Handler(void);

void Reset_Handler(void);

void Default_Handler(void)
{
    for (;;) {
    }
}

void NMI_Handler(void) __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void) __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler(void) __attribute__((weak, alias("Default_Handler")));

__attribute__((section(".vectors"), used))
const void *m33mu_vectors[] = {
    (void *)&_estack,
    (void *)Reset_Handler,
    (void *)NMI_Handler,
    (void *)HardFault_Handler,
    (void *)MemManage_Handler,
    (void *)BusFault_Handler,
    (void *)UsageFault_Handler,
    NULL, NULL, NULL, NULL,
    (void *)SVC_Handler,
    (void *)DebugMon_Handler,
    NULL,
    (void *)PendSV_Handler,
    (void *)SysTick_Handler
};

#define REG32(address) (*(volatile uint32_t *)(address))
#define RCC_AHB2ENR REG32(0x44020C8CUL)
#define RCC_APB1LENR REG32(0x44020C9CUL)
#define GPIOD_MODER REG32(0x42020C00UL)
#define GPIOD_AFRH REG32(0x42020C24UL)
#define USART3_CR1 REG32(0x40004800UL)
#define USART3_CR2 REG32(0x40004804UL)
#define USART3_CR3 REG32(0x40004808UL)
#define USART3_BRR REG32(0x4000480CUL)
#define USART3_ISR REG32(0x4000481CUL)
#define USART3_TDR REG32(0x40004828UL)

static void uart_init(void)
{
    RCC_AHB2ENR |= (1UL << 3);
    RCC_APB1LENR |= (1UL << 18);
    GPIOD_MODER = (GPIOD_MODER & ~(3UL << 16)) | (2UL << 16);
    GPIOD_AFRH = (GPIOD_AFRH & ~15UL) | 7UL;
    USART3_CR1 = 0UL;
    USART3_CR2 = 0UL;
    USART3_CR3 = 0UL;
    USART3_BRR = 278UL;
    USART3_CR1 = (1UL << 3) | (1UL << 2) | 1UL;
}

static void uart_putc(char c)
{
    while ((USART3_ISR & (1UL << 7)) == 0UL) {
    }
    USART3_TDR = (uint32_t)(unsigned char)c;
}

void Reset_Handler(void)
{
    uint32_t *source;
    uint32_t *dest;

    source = &_sidata;
    dest = &_sdata;
    while (dest < &_edata)
        *dest++ = *source++;
    dest = &_sbss;
    while (dest < &_ebss)
        *dest++ = 0UL;

    uart_init();
    (void)main();
    for (;;) {
    }
}

ssize_t _write(int fd, const void *buffer, size_t count)
{
    const unsigned char *bytes;
    size_t i;

    (void)fd;
    bytes = (const unsigned char *)buffer;
    for (i = 0; i < count; ++i) {
        if (bytes[i] == (unsigned char)'\n')
            uart_putc('\r');
        uart_putc((char)bytes[i]);
    }
    return (ssize_t)count;
}

void *_sbrk(ptrdiff_t increment)
{
    static unsigned char *current = &_heap_start;
    unsigned char *previous;

    previous = current;
    if ((increment < 0) || ((size_t)increment > (size_t)(&_heap_end - current)))
        return (void *)-1;
    current += increment;
    return previous;
}

int _close(int fd)
{
    (void)fd;
    return -1;
}

int _fstat(int fd, struct stat *state)
{
    (void)fd;
    state->st_mode = S_IFCHR;
    return 0;
}

int _isatty(int fd)
{
    (void)fd;
    return 1;
}

off_t _lseek(int fd, off_t offset, int whence)
{
    (void)fd;
    (void)offset;
    (void)whence;
    return (off_t)-1;
}

ssize_t _read(int fd, void *buffer, size_t count)
{
    (void)fd;
    (void)buffer;
    (void)count;
    return -1;
}

int _getpid(void)
{
    return 1;
}

int _kill(int pid, int signal)
{
    (void)pid;
    (void)signal;
    return -1;
}

void _exit(int status)
{
    (void)status;
    for (;;) {
    }
}
