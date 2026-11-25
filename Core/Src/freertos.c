/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * File Name          : freertos.c
  * Description        : Code for freertos applications
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "FreeRTOS.h"
#include "task.h"
#include "main.h"
#include "cmsis_os.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "lwip.h"
#include "lwip/netif.h"
#include "modbus_tcp.h"
#include "ip_discovery.h"
#include "network_identity.h"
#include "mbscan.h"
#include "lwip/netifapi.h"
#include "lwip/ip4_addr.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN Variables */
/* Debugger-only observations: startup stages, assertion location and loop counts.
 * These variables are not application commands or sensor measurements.
 */
extern volatile uint32_t lwip_stage;
const char * volatile debug_error_file = NULL;
const char * volatile debug_error_expression = NULL;
volatile uint32_t debug_error_line = 0;
volatile uint32_t lwip_init_done = 0;
volatile uint32_t led_test_cycles = 0;
extern struct netif gnetif;
extern ETH_HandleTypeDef heth;


/* Read these fields in the debugger Watch window. */
typedef struct
{
    char ip[16];
    char netmask[16];
    char gateway[16];
    char mac[18];

    uint32_t interface_up;
    uint32_t link_up;

    uint32_t modbus_port;
    uint32_t discovery_port;

    uint32_t heap_free_bytes;
    uint32_t heap_min_free_bytes;

    uint32_t uid[3];

    int32_t snapshot_status;
    uint32_t update_count;
} NetworkDebug_t;

volatile NetworkDebug_t net_dbg;
/* FreeRTOS heap measurements are bytes; minimum is the low watermark since boot.
 * net_flags_dbg and eth_state_dbg are diagnostic snapshots, not synchronization.
 */
volatile uint32_t network_free_heap = 0;
volatile uint32_t network_min_free_heap = 0;
volatile uint32_t net_flags_dbg = 0;
volatile uint32_t eth_state_dbg = 0;
/* USER CODE END Variables */
osThreadId defaultTaskHandle;
osThreadId modbusTaskHandle;
osThreadId discoveryTaskHandle;
osThreadId mbscanTaskHandle;

/* Private function prototypes -----------------------------------------------*/
/* USER CODE BEGIN FunctionPrototypes */
static void NetworkDebug_Update(void);
/* USER CODE END FunctionPrototypes */

void StartDefaultTask(void const * argument);

extern void MX_LWIP_Init(void);
void MX_FREERTOS_Init(void); /* (MISRA C 2004 rule 8.1) */

/* GetIdleTaskMemory prototype (linked to static allocation support) */
void vApplicationGetIdleTaskMemory( StaticTask_t **ppxIdleTaskTCBBuffer, StackType_t **ppxIdleTaskStackBuffer, uint32_t *pulIdleTaskStackSize );

/* USER CODE BEGIN GET_IDLE_TASK_MEMORY */
/* Static storage required by configSUPPORT_STATIC_ALLOCATION for the idle task. */
static StaticTask_t xIdleTaskTCBBuffer;
static StackType_t xIdleStack[configMINIMAL_STACK_SIZE];

void vApplicationGetIdleTaskMemory( StaticTask_t **ppxIdleTaskTCBBuffer, StackType_t **ppxIdleTaskStackBuffer, uint32_t *pulIdleTaskStackSize )
{
  *ppxIdleTaskTCBBuffer = &xIdleTaskTCBBuffer;
  *ppxIdleTaskStackBuffer = &xIdleStack[0];
  *pulIdleTaskStackSize = configMINIMAL_STACK_SIZE;
  /* place for user code */
}
/* USER CODE END GET_IDLE_TASK_MEMORY */

/**
  * @brief  FreeRTOS initialization
  * @param  None
  * @retval None
  */
/* Create the default task before scheduler start; network tasks are created later. */
void MX_FREERTOS_Init(void) {
  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* USER CODE BEGIN RTOS_MUTEX */
  /* add mutexes, ... */
  /* USER CODE END RTOS_MUTEX */

  /* USER CODE BEGIN RTOS_SEMAPHORES */
  /* add semaphores, ... */
  /* USER CODE END RTOS_SEMAPHORES */

  /* USER CODE BEGIN RTOS_TIMERS */
  /* start timers, add new ones, ... */
  /* USER CODE END RTOS_TIMERS */

  /* USER CODE BEGIN RTOS_QUEUES */
  /* add queues, ... */
  /* USER CODE END RTOS_QUEUES */

  /* Create the thread(s) */
  /* definition and creation of defaultTask */
  osThreadDef(defaultTask, StartDefaultTask, osPriorityNormal, 0, 512);
  defaultTaskHandle = osThreadCreate(osThread(defaultTask), NULL);

  /* USER CODE BEGIN RTOS_THREADS */
  /* add threads, ... */
  /* USER CODE END RTOS_THREADS */

}

/* USER CODE BEGIN Header_StartDefaultTask */
/**
  * @brief  Function implementing the defaultTask thread.
  * @param  argument: Not used
  * @retval None
  */
/* USER CODE END Header_StartDefaultTask */
/* Initialize lwIP before either Netconn service is started.
 * Task-creation failures halt through configASSERT; successful startup continues
 * with LED diagnostics and heap monitoring, not sensor acquisition.
 */
void StartDefaultTask(void const * argument)
{
  /* init code for LWIP */
  lwip_stage = 10;
  MX_LWIP_Init();
  /* USER CODE BEGIN StartDefaultTask */
  lwip_init_done = 1;
  NetworkIdentity_Start();
  /* Preserve startup order: Modbus first, discovery second, both after lwIP. */
  modbusTaskHandle = ModbusTCP_Start();
  configASSERT(modbusTaskHandle != NULL);
  discoveryTaskHandle = IPDiscovery_Start();
  configASSERT(discoveryTaskHandle != NULL);
#if MBSCAN_ENABLE
  /* Hybrid Modbus-TCP device IP discovery; owns the interface until it finishes. */
  mbscanTaskHandle = MbScan_Start();
  configASSERT(mbscanTaskHandle != NULL);
#endif
  /* Infinite loop */
  for(;;)
  {
		NetworkIdentity_Poll();
        NetworkDebug_Update();
    network_free_heap = (uint32_t)xPortGetFreeHeapSize();
    network_min_free_heap = (uint32_t)xPortGetMinimumEverFreeHeapSize();
    net_flags_dbg = (uint32_t)gnetif.flags;
    eth_state_dbg = (uint32_t)heth.State;
    /* Sequential LED toggles, each followed by 500 ms delay.
     * One monitoring loop takes at least 1500 ms; each LED toggles once per loop.
     */
    HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_2);  /* LED1 */
    osDelay(500);

    HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_3);  /* LED2 */
    osDelay(500);

    HAL_GPIO_TogglePin(GPIOD, GPIO_PIN_4);  /* LED3 */
    osDelay(500);
    ++led_test_cycles;
  }
  /* USER CODE END StartDefaultTask */
}

/* Private application code --------------------------------------------------*/
/* USER CODE BEGIN Application */
/* Fatal assertion handler shared by FreeRTOS and lwIP.
 * Inspect debug_error_file, debug_error_line and debug_error_expression.
 * Interrupts remain disabled and execution stops; this path does not recover.
 */
void debug_assert_failed(const char *file, uint32_t line,
                         const char *expression)
{
    taskDISABLE_INTERRUPTS();
    debug_error_file = file;
    debug_error_line = line;
    debug_error_expression = expression;
    for (;;)
    {
    }
}
/*
 * Convert an IPv4 address into readable text.
 * No dynamic memory allocation is used here.
 */
static void NetworkDebug_CopyIPv4(volatile char *destination,
                                  const ip4_addr_t *address)
{
    char text[16] = {0};
    uint32_t i;

    ip4addr_ntoa_r(address, text, sizeof(text));

    for (i = 0; i < sizeof(text); ++i)
    {
        destination[i] = text[i];
    }
}

/*
 * This callback runs inside lwIP's tcpip_thread.
 * Read the network interface here instead of reading it
 * directly from another task.
 */
static void NetworkDebug_Snapshot(struct netif *interface)
{
    static const char hex[] = "0123456789ABCDEF";
    uint32_t i;
    uint8_t value;

    NetworkDebug_CopyIPv4(net_dbg.ip,
                          netif_ip4_addr(interface));

    NetworkDebug_CopyIPv4(net_dbg.netmask,
                          netif_ip4_netmask(interface));

    NetworkDebug_CopyIPv4(net_dbg.gateway,
                          netif_ip4_gw(interface));

    /* Format the Ethernet MAC as XX:XX:XX:XX:XX:XX. */
    for (i = 0; i < 6U; ++i)
    {
        value = interface->hwaddr[i];

        net_dbg.mac[3U * i] =
            hex[(value >> 4) & 0x0FU];

        net_dbg.mac[3U * i + 1U] =
            hex[value & 0x0FU];

        if (i < 5U)
        {
            net_dbg.mac[3U * i + 2U] = ':';
        }
    }

    net_dbg.mac[17] = '\0';

    /* Administrative state and physical link state are different. */
    net_dbg.interface_up = netif_is_up(interface) ? 1U : 0U;
    net_dbg.link_up = netif_is_link_up(interface) ? 1U : 0U;
}

/*
 * Call this function from the default task after MX_LWIP_Init().
 * Do not call it from an interrupt or from tcpip_thread itself.
 */
static void NetworkDebug_Update(void)
{
    err_t status;

    status = netifapi_netif_common(&gnetif,
                                   NetworkDebug_Snapshot,
                                   NULL);

    net_dbg.snapshot_status = (int32_t)status;

    net_dbg.modbus_port = 502U;
    net_dbg.discovery_port = 30303U;

    net_dbg.heap_free_bytes =
        (uint32_t)xPortGetFreeHeapSize();

    net_dbg.heap_min_free_bytes =
        (uint32_t)xPortGetMinimumEverFreeHeapSize();

    net_dbg.uid[0] = HAL_GetUIDw0();
    net_dbg.uid[1] = HAL_GetUIDw1();
    net_dbg.uid[2] = HAL_GetUIDw2();

    if (status == ERR_OK)
    {
        ++net_dbg.update_count;
    }
}

/* USER CODE END Application */

