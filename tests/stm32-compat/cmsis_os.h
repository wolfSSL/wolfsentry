/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef WOLFSENTRY_TEST_CMSIS_OS_H
#define WOLFSENTRY_TEST_CMSIS_OS_H

#include <stdint.h>

typedef void *QueueHandle_t;
typedef int BaseType_t;
typedef uint32_t TickType_t;

typedef enum {
    osOK = 0
} osStatus;

#define pdPASS 1

BaseType_t xQueueSendFromISR(QueueHandle_t queue, const void *item,
    BaseType_t *higher_priority_task_woken);
osStatus osDelay(uint32_t millisec);

#endif /* WOLFSENTRY_TEST_CMSIS_OS_H */
