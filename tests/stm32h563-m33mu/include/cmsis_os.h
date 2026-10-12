/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef WOLFSENTRY_M33MU_CMSIS_OS_H
#define WOLFSENTRY_M33MU_CMSIS_OS_H

#include "FreeRTOS.h"
#include "queue.h"
#include "task.h"

typedef int osStatus;

#define osOK 0

static __inline__ osStatus osDelay(uint32_t millisec)
{
    vTaskDelay(pdMS_TO_TICKS(millisec));
    return osOK;
}

#endif /* WOLFSENTRY_M33MU_CMSIS_OS_H */
