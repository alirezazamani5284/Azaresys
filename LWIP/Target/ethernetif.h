/* USER CODE BEGIN Header */
/**
 ******************************************************************************
  * File Name          : ethernetif.h
  * Description        : This file provides initialization code for LWIP
  *                      middleWare.
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

#ifndef __ETHERNETIF_H__
#define __ETHERNETIF_H__
#include "lwip/err.h"
#include "lwip/netif.h"
#include "cmsis_os.h"

/* Exported types ------------------------------------------------------------*/
/* Structure that include link thread parameters */
struct link_str {
  struct netif *netif;
  osSemaphoreId semaphore;
};

/* Within 'USER CODE' section, code will be kept by default at each generation */
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* Exported functions ------------------------------------------------------- */
/* Interface callback passed to netif_add; connects the STM32 MAC/DMA to lwIP. */
err_t ethernetif_init(struct netif *netif);

void ethernetif_set_link(void const *argument);
void ethernetif_update_config(struct netif *netif);
void ethernetif_notify_conn_changed(struct netif *netif);

void Error_Handler(void);
u32_t sys_jiffies(void);
u32_t sys_now(void);

/* USER CODE BEGIN 1 */
/* Discovery scanner hooks (see mbscan.c). */
extern void (* volatile ethernetif_rx_tap)(const uint8_t *frame, uint16_t length);
extern volatile uint16_t ethernetif_vlan_id;
int ethernetif_send_raw(const uint8_t *frame, uint16_t length, uint32_t wait_ms);
void ethernetif_read_counters(uint32_t *crc_errors, uint32_t *align_errors, uint32_t *missed);


/* USER CODE END 1 */
#endif
