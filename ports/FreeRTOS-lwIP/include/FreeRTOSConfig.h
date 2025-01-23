/*
 * FreeRTOS/include/FreeRTOSConfig.h
 *
 * Copyright (C) 2022-2025 wolfSSL Inc.
 *
 * This file is part of wolfSentry.
 *
 * wolfSentry is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSentry is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* placeholder FreeRTOSConfig.h for test builds of libwolfsentry --
 * for actual applications, build libwolfsentry with the same FreeRTOSConfig.h
 * and FreeRTOS headers as the application.
 */

#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#define configUSE_TRACE_FACILITY                0
#define configGENERATE_RUN_TIME_STATS           0

#define configUSE_TICKLESS_IDLE                 0
#define configUSE_PREEMPTION                    1
#define configUSE_IDLE_HOOK                     0
#define configUSE_TICK_HOOK                     1
#define configCPU_CLOCK_HZ                      25000000UL
#define configTICK_RATE_HZ                      1000
#define configMINIMAL_STACK_SIZE                512
#define configTOTAL_HEAP_SIZE                   (512UL * 1024UL)
#define configMAX_TASK_NAME_LEN                 12
#define configUSE_16_BIT_TICKS                  0
#define configIDLE_SHOULD_YIELD                 0
#define configUSE_MUTEXES                       1
#define configUSE_RECURSIVE_MUTEXES             1
#define configCHECK_FOR_STACK_OVERFLOW          2
#define configUSE_MALLOC_FAILED_HOOK            1
#define configUSE_QUEUE_SETS                    1
#define configUSE_COUNTING_SEMAPHORES           1

#define configMAX_PRIORITIES                    9UL
#define configQUEUE_REGISTRY_SIZE               10
#define configSUPPORT_STATIC_ALLOCATION         1

#define configUSE_TIMERS                        1
#define configTIMER_TASK_PRIORITY               ( configMAX_PRIORITIES - 4 )
#define configTIMER_QUEUE_LENGTH                20
#define configTIMER_TASK_STACK_DEPTH            ( configMINIMAL_STACK_SIZE * 2 )

#define configUSE_TASK_NOTIFICATIONS            1
#define configTASK_NOTIFICATION_ARRAY_ENTRIES   3

#define INCLUDE_vTaskPrioritySet                1
#define INCLUDE_uxTaskPriorityGet               1
#define INCLUDE_vTaskDelete                     1
#define INCLUDE_vTaskCleanUpResources           0
#define INCLUDE_vTaskSuspend                    1
#define INCLUDE_vTaskDelayUntil                 1
#define INCLUDE_vTaskDelay                      1
#define INCLUDE_uxTaskGetStackHighWaterMark     1
#define INCLUDE_xTaskGetSchedulerState          1
#define INCLUDE_xTimerGetTimerDaemonTaskHandle  1
#define INCLUDE_xTaskGetIdleTaskHandle          1
#define INCLUDE_xSemaphoreGetMutexHolder        1
#define INCLUDE_eTaskGetState                   1
#define INCLUDE_xTimerPendFunctionCall          1
#define INCLUDE_xTaskAbortDelay                 1
#define INCLUDE_xTaskGetHandle                  1
#define INCLUDE_xTaskGetCurrentTaskHandle       1

#define configUSE_STATS_FORMATTING_FUNCTIONS    0

#define configKERNEL_INTERRUPT_PRIORITY         255
#define configMAX_SYSCALL_INTERRUPT_PRIORITY    5

#define configUSE_PORT_OPTIMISED_TASK_SELECTION 1

#ifndef __IASMARM__ /* Prevent C code being included in IAR asm files. */
        void vAssertCalled( const char *pcFileName, uint32_t ulLine );
        #define configASSERT( x ) if( ( x ) == 0 ) vAssertCalled( __FILE__, __LINE__ );
#endif

#endif /* FREERTOS_CONFIG_H */
