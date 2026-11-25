/*
 * FreeRTOS Kernel V10.3.1
 * Portion Copyright (C) 2017 Amazon.com, Inc. or its affiliates.
 * Portion Copyright (C) 2019 STMicroelectronics.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
 * OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

/* USER CODE BEGIN Includes */
/* USER CODE END Includes */

#if defined(__ICCARM__) || defined(__CC_ARM) || defined(__GNUC__)
    #include <stdint.h>
    extern uint32_t SystemCoreClock;
#endif

/* Processor configuration. */
#define configENABLE_FPU                         0
#define configENABLE_MPU                         0

/* Scheduler configuration. */
#define configUSE_PREEMPTION                     1
#define configCPU_CLOCK_HZ                       (SystemCoreClock)
/* RTOS tick: 1000 Hz (1 ms). Stack depths in this port are 32-bit words. */
#define configTICK_RATE_HZ                       ((TickType_t)1000)
#define configMAX_PRIORITIES                     7
#define configMINIMAL_STACK_SIZE                 ((uint16_t)128)
#define configMAX_TASK_NAME_LEN                  16
#define configUSE_16_BIT_TICKS                    0
#define configUSE_PORT_OPTIMISED_TASK_SELECTION   1

/* Memory allocation. */
#define configSUPPORT_STATIC_ALLOCATION          1
#define configSUPPORT_DYNAMIC_ALLOCATION         1
/* RTOS heap budget: 16384 bytes; separate from the lwIP MEM_SIZE pool. */
/* 16384 + 4096: the discovery scanner task (512 words) and its RTOS objects. */
#define configTOTAL_HEAP_SIZE                    ((size_t)20480)

/* Synchronization. */
#define configUSE_MUTEXES                        1
#define configQUEUE_REGISTRY_SIZE                8

/* Application hooks. */
#define configUSE_IDLE_HOOK                      0
#define configUSE_TICK_HOOK                      0

/* USER CODE BEGIN MESSAGE_BUFFER_LENGTH_TYPE */
#define configMESSAGE_BUFFER_LENGTH_TYPE         size_t
/* USER CODE END MESSAGE_BUFFER_LENGTH_TYPE */

/* Co-routines. */
#define configUSE_CO_ROUTINES                    0
#define configMAX_CO_ROUTINE_PRIORITIES          2

/* Optional API functions. */
#define INCLUDE_vTaskPrioritySet                 1
#define INCLUDE_uxTaskPriorityGet                1
#define INCLUDE_vTaskDelete                      1
#define INCLUDE_vTaskCleanUpResources             0
#define INCLUDE_vTaskSuspend                     1
#define INCLUDE_vTaskDelayUntil                  0
#define INCLUDE_vTaskDelay                       1
#define INCLUDE_xTaskGetSchedulerState           1

/* Cortex-M interrupt priority configuration. */
#ifdef __NVIC_PRIO_BITS
    #define configPRIO_BITS                      __NVIC_PRIO_BITS
#else
    #define configPRIO_BITS                      4
#endif

#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY       15
/* ISRs using RTOS APIs must respect this Cortex-M priority threshold. */
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY  5

#define configKERNEL_INTERRUPT_PRIORITY                          \
    (configLIBRARY_LOWEST_INTERRUPT_PRIORITY <<                   \
     (8 - configPRIO_BITS))

#define configMAX_SYSCALL_INTERRUPT_PRIORITY                     \
    (configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY <<              \
     (8 - configPRIO_BITS))

/* USER CODE BEGIN 1 */

/*
 * On assertion failure, stop execution and retain the source location.
 * Inspect these local variables in the debugger's Locals window:
 *
 *     rtos_assert_file
 *     rtos_assert_line
 */
/* Actual retained watch symbols are debug_error_file, debug_error_line and
 * debug_error_expression in freertos.c. The older Locals example above is historical.
 */
void debug_assert_failed(const char *file, uint32_t line,
                         const char *expression);

#define configASSERT(condition)                                  \
    do                                                           \
    {                                                            \
        if ((condition) == 0)                                    \
        {                                                        \
            debug_assert_failed(__FILE__, (uint32_t)__LINE__,      \
                                #condition);                     \
        }                                                        \
    } while (0)

/* USER CODE END 1 */

/* FreeRTOS exception handlers. */
#define vPortSVCHandler                          SVC_Handler
#define xPortPendSVHandler                       PendSV_Handler

/* HAL uses TIM2. FreeRTOS uses SysTick. */
#define xPortSysTickHandler                      SysTick_Handler

/* USER CODE BEGIN Defines */

/* Enable measurement of remaining task stack space. */
#define INCLUDE_uxTaskGetStackHighWaterMark       1

/* USER CODE END Defines */

#endif /* FREERTOS_CONFIG_H */
