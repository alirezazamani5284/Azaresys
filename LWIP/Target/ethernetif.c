/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * File Name          : ethernetif.c
  * Description        : This file provides code for the configuration
  *                      of the Target/ethernetif.c MiddleWare.
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
#include "main.h"
#include "lwip/opt.h"

#include "lwip/timeouts.h"
#include "netif/ethernet.h"
#include "netif/etharp.h"
#include "lwip/ethip6.h"
#include "ethernetif.h"
#include "network_identity.h"
#include "lwip/netifapi.h"
#include <string.h>
#include "cmsis_os.h"
#include "lwip/tcpip.h"
/* Within 'USER CODE' section, code will be kept by default at each generation */
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/* Private define ------------------------------------------------------------*/
/* The time to block waiting for input. */
#define TIME_WAITING_FOR_INPUT ( portMAX_DELAY )
/* USER CODE BEGIN OS_THREAD_STACK_SIZE_WITH_RTOS */
/* Stack size of the interface thread */
#define INTERFACE_THREAD_STACK_SIZE ( 350 )
/* USER CODE END OS_THREAD_STACK_SIZE_WITH_RTOS */
/* Network interface name */
#define IFNAME0 's'
#define IFNAME1 't'

/* USER CODE BEGIN 1 */

/* USER CODE END 1 */

/* Private variables ---------------------------------------------------------*/
#if defined ( __ICCARM__ ) /*!< IAR Compiler */
  #pragma data_alignment=4
#endif
/* DMA descriptor and frame storage must retain the existing alignment and sizes.
 * Rx/Tx buffer ownership is transferred using descriptor OWN bits.
 */
__ALIGN_BEGIN ETH_DMADescTypeDef  DMARxDscrTab[ETH_RXBUFNB] __ALIGN_END;/* Ethernet Rx MA Descriptor */

#if defined ( __ICCARM__ ) /*!< IAR Compiler */
  #pragma data_alignment=4
#endif
__ALIGN_BEGIN ETH_DMADescTypeDef  DMATxDscrTab[ETH_TXBUFNB] __ALIGN_END;/* Ethernet Tx DMA Descriptor */

#if defined ( __ICCARM__ ) /*!< IAR Compiler */
  #pragma data_alignment=4
#endif
__ALIGN_BEGIN uint8_t Rx_Buff[ETH_RXBUFNB][ETH_RX_BUF_SIZE] __ALIGN_END; /* Ethernet Receive Buffer */

#if defined ( __ICCARM__ ) /*!< IAR Compiler */
  #pragma data_alignment=4
#endif
__ALIGN_BEGIN uint8_t Tx_Buff[ETH_TXBUFNB][ETH_TX_BUF_SIZE] __ALIGN_END; /* Ethernet Transmit Buffer */

/* USER CODE BEGIN 2 */
extern volatile uint32_t lwip_stage;
volatile uint32_t eth_init_result = 0xFFFFFFFFU;
volatile uint32_t eth_start_result = 0xFFFFFFFFU;
volatile uint32_t eth_rx_callback_count = 0;
/* Raw receive tap (discovery scanner): sees every frame BEFORE lwIP. Runs in the
 * Ethernet input task, so it must be short and must not block. NULL = off. */
void (* volatile ethernetif_rx_tap)(const uint8_t *frame, uint16_t length) = NULL;
/* 802.1Q VID used for all lwIP traffic; 0 = untagged. Set by the scanner when the
 * peer port turns out to be VLAN tagged. Tx frames get the tag, matching Rx are untagged. */
volatile uint16_t ethernetif_vlan_id = 0;
/* USER CODE END 2 */

/* Semaphore to signal incoming packets */
osSemaphoreId s_xSemaphore = NULL;
/* Global Ethernet handle */
ETH_HandleTypeDef heth;
extern struct netif gnetif;

/* Private function prototypes -----------------------------------------------*/
static void ethernetif_input(void const * argument);

/* USER CODE BEGIN 3 */

/* USER CODE END 3 */

/* Private functions ---------------------------------------------------------*/

/* Board pin map: MDC PC1, MDIO PA2, REF_CLK PA1; TX PB11/PB12/PB13;
 * remapped RX PD8/PD9/PD10. Ethernet IRQ priority 5 matches the RTOS API threshold.
 */
void HAL_ETH_MspInit(ETH_HandleTypeDef* ethHandle)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  if(ethHandle->Instance==ETH)
  {
  /* USER CODE BEGIN ETH_MspInit 0 */

  /* USER CODE END ETH_MspInit 0 */
    /* Enable Peripheral clock */
    __HAL_RCC_ETH_CLK_ENABLE();

    __HAL_RCC_GPIOC_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_GPIOD_CLK_ENABLE();
    /**ETH GPIO Configuration
    PC1     ------> ETH_MDC
    PA1     ------> ETH_REF_CLK
    PA2     ------> ETH_MDIO
    PB11     ------> ETH_TX_EN
    PB12     ------> ETH_TXD0
    PB13     ------> ETH_TXD1
    PD8     ------> ETH_CRS_DV
    PD9     ------> ETH_RXD0
    PD10     ------> ETH_RXD1
    */
    GPIO_InitStruct.Pin = GPIO_PIN_1;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_1;
    GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_2;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_11|GPIO_PIN_12|GPIO_PIN_13;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
    HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_8|GPIO_PIN_9|GPIO_PIN_10;
    GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

    __HAL_AFIO_REMAP_ETH_ENABLE();

    /* Peripheral interrupt init */
    HAL_NVIC_SetPriority(ETH_IRQn, 5, 0);
    HAL_NVIC_EnableIRQ(ETH_IRQn);
  /* USER CODE BEGIN ETH_MspInit 1 */

  /* USER CODE END ETH_MspInit 1 */
  }
}

/* Undo Ethernet clocks, pin setup and IRQ enable for this hardware instance. */
void HAL_ETH_MspDeInit(ETH_HandleTypeDef* ethHandle)
{
  if(ethHandle->Instance==ETH)
  {
  /* USER CODE BEGIN ETH_MspDeInit 0 */

  /* USER CODE END ETH_MspDeInit 0 */
    /* Disable Peripheral clock */
    __HAL_RCC_ETH_CLK_DISABLE();

    /**ETH GPIO Configuration
    PC1     ------> ETH_MDC
    PA1     ------> ETH_REF_CLK
    PA2     ------> ETH_MDIO
    PB11     ------> ETH_TX_EN
    PB12     ------> ETH_TXD0
    PB13     ------> ETH_TXD1
    PD8     ------> ETH_CRS_DV
    PD9     ------> ETH_RXD0
    PD10     ------> ETH_RXD1
    */
    HAL_GPIO_DeInit(GPIOC, GPIO_PIN_1);

    HAL_GPIO_DeInit(GPIOA, GPIO_PIN_1|GPIO_PIN_2);

    HAL_GPIO_DeInit(GPIOB, GPIO_PIN_11|GPIO_PIN_12|GPIO_PIN_13);

    HAL_GPIO_DeInit(GPIOD, GPIO_PIN_8|GPIO_PIN_9|GPIO_PIN_10);

    /* Peripheral interrupt Deinit*/
    HAL_NVIC_DisableIRQ(ETH_IRQn);

  /* USER CODE BEGIN ETH_MspDeInit 1 */

  /* USER CODE END ETH_MspDeInit 1 */
  }
}

/**
  * @brief  Ethernet Rx Transfer completed callback
  * @param  heth: ETH handle
  * @retval None
  */
/* ISR callback: count reception events and wake the Ethernet input task.
 * Packet copying and stack processing occur later in task context.
 */
void HAL_ETH_RxCpltCallback(ETH_HandleTypeDef *heth)
{
    ++eth_rx_callback_count;
    osSemaphoreRelease(s_xSemaphore);
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/*******************************************************************************
                       LL Driver Interface ( LwIP stack --> ETH)
*******************************************************************************/
/**
 * In this function, the hardware should be initialized.
 * Called from ethernetif_init().
 *
 * @param netif the already initialized lwip network interface structure
 *        for this ethernetif
 */
/* Driver setup retains fixed MAC 00:80:E1:00:00:00, RMII, interrupt reception
 * and software checksums. Auto-negotiation determines the operational link mode.
 * Creates Rx semaphore/task, prepares DMA chains and starts the MAC.
 * Distinct boards need distinct IP/MAC provisioning; no automatic assignment exists.
 */
static void low_level_init(struct netif *netif)
{
  HAL_StatusTypeDef hal_eth_init_status;
  osThreadId eth_input_task;

/* Init ETH */

  static uint8_t MACAddr[6];
  heth.Instance = ETH;
  heth.Init.AutoNegotiation = ETH_AUTONEGOTIATION_ENABLE;
  heth.Init.Speed = ETH_SPEED_100M;
  heth.Init.DuplexMode = ETH_MODE_FULLDUPLEX;
  heth.Init.PhyAddress = LAN8742A_PHY_ADDRESS;
  /* Stable locally administered MAC; do not reuse one factory MAC on all boards. */
  NetworkIdentity_MakeMAC(MACAddr);
  heth.Init.MACAddr = &MACAddr[0];
  heth.Init.RxMode = ETH_RXINTERRUPT_MODE;
  heth.Init.ChecksumMode = ETH_CHECKSUM_BY_SOFTWARE;
  heth.Init.MediaInterface = ETH_MEDIA_INTERFACE_RMII;

  /* USER CODE BEGIN MACADDRESS */

  /* USER CODE END MACADDRESS */

  lwip_stage = 21;
  hal_eth_init_status = HAL_ETH_Init(&heth);
  lwip_stage = 22;
  eth_init_result = (uint32_t)hal_eth_init_status;
  if (hal_eth_init_status == HAL_OK)
  {
    /* Set netif link flag */
    netif->flags |= NETIF_FLAG_LINK_UP;
  }
  /* Initialize Tx Descriptors list: Chain Mode */
  HAL_ETH_DMATxDescListInit(&heth, DMATxDscrTab, &Tx_Buff[0][0], ETH_TXBUFNB);

  /* Initialize Rx Descriptors list: Chain Mode  */
  HAL_ETH_DMARxDescListInit(&heth, DMARxDscrTab, &Rx_Buff[0][0], ETH_RXBUFNB);

#if LWIP_ARP || LWIP_ETHERNET

  /* set MAC hardware address length */
  netif->hwaddr_len = ETH_HWADDR_LEN;

  /* set MAC hardware address */
  netif->hwaddr[0] =  heth.Init.MACAddr[0];
  netif->hwaddr[1] =  heth.Init.MACAddr[1];
  netif->hwaddr[2] =  heth.Init.MACAddr[2];
  netif->hwaddr[3] =  heth.Init.MACAddr[3];
  netif->hwaddr[4] =  heth.Init.MACAddr[4];
  netif->hwaddr[5] =  heth.Init.MACAddr[5];

  /* maximum transfer unit */
  netif->mtu = 1500;

  /* Accept broadcast address and ARP traffic */
  /* don't set NETIF_FLAG_ETHARP if this device is not an ethernet one */
  #if LWIP_ARP
    netif->flags |= NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;
  #else
    netif->flags |= NETIF_FLAG_BROADCAST;
  #endif /* LWIP_ARP */

/* create a binary semaphore used for informing ethernetif of frame reception */
  osSemaphoreDef(SEM);
  s_xSemaphore = osSemaphoreCreate(osSemaphore(SEM), 1);
  LWIP_ASSERT("Ethernet receive semaphore allocation failed", s_xSemaphore != NULL);
  lwip_stage = 23;

/* create the task that handles the ETH_MAC */
/* USER CODE BEGIN OS_THREAD_DEF_CREATE_CMSIS_RTOS_V1 */
  osThreadDef(EthIf, ethernetif_input, osPriorityRealtime, 0, INTERFACE_THREAD_STACK_SIZE);
  eth_input_task = osThreadCreate(osThread(EthIf), netif);
  LWIP_ASSERT("Ethernet receive task allocation failed", eth_input_task != NULL);
  lwip_stage = 24;
/* USER CODE END OS_THREAD_DEF_CREATE_CMSIS_RTOS_V1 */
  /* Enable MAC and DMA transmission and reception */
  eth_start_result = (uint32_t)HAL_ETH_Start(&heth);
  lwip_stage = 25;

/* USER CODE BEGIN PHY_PRE_CONFIG */

/* USER CODE END PHY_PRE_CONFIG */

  /* Link status is polled; no PHY-specific interrupt register writes. */

/* USER CODE BEGIN PHY_POST_CONFIG */

/* USER CODE END PHY_POST_CONFIG */

#endif /* LWIP_ARP || LWIP_ETHERNET */

/* USER CODE BEGIN LOW_LEVEL_INIT */

/* USER CODE END LOW_LEVEL_INIT */
}

/**
 * This function should do the actual transmission of the packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * might be chained.
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @param p the MAC packet to send (e.g. IP packet including MAC addresses and type)
 * @return ERR_OK if the packet could be sent
 *         an err_t value if the packet couldn't be sent
 *
 * @note Returning ERR_MEM here if a DMA queue of your MAC is full can lead to
 *       strange results. You might consider waiting for space in the DMA queue
 *       to become available since the stack doesn't retry to send a packet
 *       dropped because of memory failure (except for the TCP timers).
 */

/* Copy a chained lwIP pbuf into DMA Tx buffers before submitting the frame.
 * A busy descriptor returns ERR_USE. The existing HAL transmit result is not checked
 * here; ERR_OK is this function result, not an end-to-end delivery acknowledgement.
 */
static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
  err_t errval;
  struct pbuf *q;
  uint8_t *buffer = (uint8_t *)(heth.TxDesc->Buffer1Addr);
  __IO ETH_DMADescTypeDef *DmaTxDesc;
  uint32_t framelength = 0;
  uint32_t bufferoffset = 0;
  uint32_t byteslefttocopy = 0;
  uint32_t payloadoffset = 0;
  DmaTxDesc = heth.TxDesc;
  bufferoffset = 0;

  /* copy frame from pbufs to driver buffers */
  for(q = p; q != NULL; q = q->next)
    {
      /* Is this buffer available? If not, goto error */
      if((DmaTxDesc->Status & ETH_DMATXDESC_OWN) != (uint32_t)RESET)
      {
        errval = ERR_USE;
        goto error;
      }

      /* Get bytes in current lwIP buffer */
      byteslefttocopy = q->len;
      payloadoffset = 0;

      /* Check if the length of data to copy is bigger than Tx buffer size*/
      while( (byteslefttocopy + bufferoffset) > ETH_TX_BUF_SIZE )
      {
        /* Copy data to Tx buffer*/
        memcpy( (uint8_t*)((uint8_t*)buffer + bufferoffset), (uint8_t*)((uint8_t*)q->payload + payloadoffset), (ETH_TX_BUF_SIZE - bufferoffset) );

        /* Point to next descriptor */
        DmaTxDesc = (ETH_DMADescTypeDef *)(DmaTxDesc->Buffer2NextDescAddr);

        /* Check if the buffer is available */
        if((DmaTxDesc->Status & ETH_DMATXDESC_OWN) != (uint32_t)RESET)
        {
          errval = ERR_USE;
          goto error;
        }

        buffer = (uint8_t *)(DmaTxDesc->Buffer1Addr);

        byteslefttocopy = byteslefttocopy - (ETH_TX_BUF_SIZE - bufferoffset);
        payloadoffset = payloadoffset + (ETH_TX_BUF_SIZE - bufferoffset);
        framelength = framelength + (ETH_TX_BUF_SIZE - bufferoffset);
        bufferoffset = 0;
      }

      /* Copy the remaining bytes */
      memcpy( (uint8_t*)((uint8_t*)buffer + bufferoffset), (uint8_t*)((uint8_t*)q->payload + payloadoffset), byteslefttocopy );
      bufferoffset = bufferoffset + byteslefttocopy;
      framelength = framelength + byteslefttocopy;
    }

  /* Insert the 802.1Q tag (single descriptor frames only). */
  if (ethernetif_vlan_id != 0 && DmaTxDesc == heth.TxDesc && framelength >= 14 &&
      framelength + 4 <= ETH_TX_BUF_SIZE)
  {
    uint8_t *tb = (uint8_t *)(heth.TxDesc->Buffer1Addr);
    memmove(tb + 16, tb + 12, framelength - 12);
    tb[12] = 0x81;
    tb[13] = 0x00;
    tb[14] = (uint8_t)(ethernetif_vlan_id >> 8);
    tb[15] = (uint8_t)ethernetif_vlan_id;
    framelength += 4;
  }

  /* Prepare transmit descriptors to give to DMA */
  HAL_ETH_TransmitFrame(&heth, framelength);

  errval = ERR_OK;

error:

  /* When Transmit Underflow flag is set, clear it and issue a Transmit Poll Demand to resume transmission */
  if ((heth.Instance->DMASR & ETH_DMASR_TUS) != (uint32_t)RESET)
  {
    /* Clear TUS ETHERNET DMA flag */
    heth.Instance->DMASR = ETH_DMASR_TUS;

    /* Resume DMA transmission*/
    heth.Instance->DMATPDR = 0;
  }
  return errval;
}

/**
 * Should allocate a pbuf and transfer the bytes of the incoming
 * packet from the interface into the pbuf.
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @return a pbuf filled with the received packet (including MAC header)
 *         NULL on memory error
   */
/* Copy a received DMA frame into an allocated lwIP pbuf chain.
 * Return NULL when no frame or no pbuf is available. Release consumed descriptors
 * back to DMA even when allocation fails, and resume Rx after buffer-unavailable.
 */
static struct pbuf * low_level_input(struct netif *netif)
{
  struct pbuf *p = NULL;
  struct pbuf *q = NULL;
  uint16_t len = 0;
  uint8_t *buffer;
  __IO ETH_DMADescTypeDef *dmarxdesc;
  uint32_t bufferoffset = 0;
  uint32_t payloadoffset = 0;
  uint32_t byteslefttocopy = 0;
  uint32_t i=0;

  /* get received frame */
  if (HAL_ETH_GetReceivedFrame_IT(&heth) != HAL_OK)

    return NULL;

  /* Obtain the size of the packet and put it into the "len" variable. */
  len = heth.RxFrameInfos.length;
  buffer = (uint8_t *)heth.RxFrameInfos.buffer;

  /* Discovery tap: first (and normally only) descriptor of the frame. */
  if (ethernetif_rx_tap != NULL && len > 0 && len <= ETH_RX_BUF_SIZE &&
      heth.RxFrameInfos.SegCount == 1)
  {
    ethernetif_rx_tap(buffer, len);
  }

  if (len > 0)
  {
    /* We allocate a pbuf chain of pbufs from the Lwip buffer pool */
    p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
  }

  if (p != NULL)
  {
    dmarxdesc = heth.RxFrameInfos.FSRxDesc;
    bufferoffset = 0;
    for(q = p; q != NULL; q = q->next)
    {
      byteslefttocopy = q->len;
      payloadoffset = 0;

      /* Check if the length of bytes to copy in current pbuf is bigger than Rx buffer size*/
      while( (byteslefttocopy + bufferoffset) > ETH_RX_BUF_SIZE )
      {
        /* Copy data to pbuf */
        memcpy( (uint8_t*)((uint8_t*)q->payload + payloadoffset), (uint8_t*)((uint8_t*)buffer + bufferoffset), (ETH_RX_BUF_SIZE - bufferoffset));

        /* Point to next descriptor */
        dmarxdesc = (ETH_DMADescTypeDef *)(dmarxdesc->Buffer2NextDescAddr);
        buffer = (uint8_t *)(dmarxdesc->Buffer1Addr);

        byteslefttocopy = byteslefttocopy - (ETH_RX_BUF_SIZE - bufferoffset);
        payloadoffset = payloadoffset + (ETH_RX_BUF_SIZE - bufferoffset);
        bufferoffset = 0;
      }
      /* Copy remaining data in pbuf */
      memcpy( (uint8_t*)((uint8_t*)q->payload + payloadoffset), (uint8_t*)((uint8_t*)buffer + bufferoffset), byteslefttocopy);
      bufferoffset = bufferoffset + byteslefttocopy;
    }
  }

  /* Strip the 802.1Q tag of the configured VLAN so lwIP sees an untagged frame. */
  if (p != NULL && ethernetif_vlan_id != 0 && p->next == NULL && p->len >= 18)
  {
    uint8_t *f = (uint8_t *)p->payload;
    if (f[12] == 0x81 && f[13] == 0x00 &&
        (uint16_t)(((f[14] << 8) | f[15]) & 0x0FFF) == ethernetif_vlan_id)
    {
      memmove(f + 12, f + 16, p->len - 16);
      p->len = (u16_t)(p->len - 4);
      p->tot_len = (u16_t)(p->tot_len - 4);
    }
  }

    /* Release descriptors to DMA */
    /* Point to first descriptor */
    dmarxdesc = heth.RxFrameInfos.FSRxDesc;
    /* Set Own bit in Rx descriptors: gives the buffers back to DMA */
    for (i=0; i< heth.RxFrameInfos.SegCount; i++)
    {
      dmarxdesc->Status |= ETH_DMARXDESC_OWN;
      dmarxdesc = (ETH_DMADescTypeDef *)(dmarxdesc->Buffer2NextDescAddr);
    }

    /* Clear Segment_Count */
    heth.RxFrameInfos.SegCount =0;

  /* When Rx Buffer unavailable flag is set: clear it and resume reception */
  if ((heth.Instance->DMASR & ETH_DMASR_RBUS) != (uint32_t)RESET)
  {
    /* Clear RBUS ETHERNET DMA flag */
    heth.Instance->DMASR = ETH_DMASR_RBUS;
    /* Resume DMA reception */
    heth.Instance->DMARPDR = 0;
  }
  return p;
}

/**
 * This function should be called when a packet is ready to be read
 * from the interface. It uses the function low_level_input() that
 * should handle the actual reception of bytes from the network
 * interface. Then the type of the received packet is determined and
 * the appropriate input function is called.
 *
 * @param netif the lwip network interface structure for this ethernetif
 */
/* Wait for Rx notification, then drain available frames.
 * On successful netif->input, ownership passes to lwIP; on failure, free the pbuf.
 * Keep existing LOCK_TCPIP_CORE configuration and call ordering unchanged.
 */
static void ethernetif_input(void const * argument)
{
  struct pbuf *p;
  struct netif *netif = (struct netif *) argument;

  for( ;; )
  {
    if (osSemaphoreWait(s_xSemaphore, TIME_WAITING_FOR_INPUT) == osOK)
    {
      do
      {
        LOCK_TCPIP_CORE();
        p = low_level_input( netif );
        if   (p != NULL)
        {
          if (netif->input( p, netif) != ERR_OK )
          {
            pbuf_free(p);
          }
        }
        UNLOCK_TCPIP_CORE();
      } while(p!=NULL);
    }
  }
}

#if !LWIP_ARP
/**
 * This function has to be completed by user in case of ARP OFF.
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @return ERR_OK if ...
 */
/* Inactive compatibility stub for ARP-disabled builds; not a complete Tx path. */
static err_t low_level_output_arp_off(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr)
{
  err_t errval;
  errval = ERR_OK;

/* USER CODE BEGIN 5 */

/* USER CODE END 5 */

  return errval;

}
#endif /* LWIP_ARP */

/**
 * Should be called at the beginning of the program to set up the
 * network interface. It calls the function low_level_init() to do the
 * actual setup of the hardware.
 *
 * This function should be passed as a parameter to netif_add().
 *
 * @param netif the lwip network interface structure for this ethernetif
 * @return ERR_OK if the loopif is initialized
 *         ERR_MEM if private data couldn't be allocated
 *         any other err_t on error
 */
/* Install ARP/IPv4, optional IPv6 and raw Ethernet output callbacks, then init MAC.
 * The returned ERR_OK does not replace checking eth_init_result/eth_start_result.
 */
err_t ethernetif_init(struct netif *netif)
{
  LWIP_ASSERT("netif != NULL", (netif != NULL));

#if LWIP_NETIF_HOSTNAME
  /* Initialize interface hostname */
  netif->hostname = "lwip";
#endif /* LWIP_NETIF_HOSTNAME */

  netif->name[0] = IFNAME0;
  netif->name[1] = IFNAME1;
  /* We directly use etharp_output() here to save a function call.
   * You can instead declare your own function an call etharp_output()
   * from it if you have to do some checks before sending (e.g. if link
   * is available...) */

#if LWIP_IPV4
#if LWIP_ARP || LWIP_ETHERNET
#if LWIP_ARP
  netif->output = etharp_output;
#else
  /* The user should write its own code in low_level_output_arp_off function */
  netif->output = low_level_output_arp_off;
#endif /* LWIP_ARP */
#endif /* LWIP_ARP || LWIP_ETHERNET */
#endif /* LWIP_IPV4 */

#if LWIP_IPV6
  netif->output_ip6 = ethip6_output;
#endif /* LWIP_IPV6 */

  netif->linkoutput = low_level_output;

  /* initialize the hardware */
  low_level_init(netif);

  return ERR_OK;
}

/* USER CODE BEGIN 6 */

/**
* @brief  Returns the current time in milliseconds
*         when LWIP_TIMERS == 1 and NO_SYS == 1
* @param  None
* @retval Time
*/
/* HAL_GetTick returns elapsed milliseconds from the TIM2 HAL time base. */
u32_t sys_jiffies(void)
{
  return HAL_GetTick();
}

/**
* @brief  Returns the current time in milliseconds
*         when LWIP_TIMERS == 1 and NO_SYS == 1
* @param  None
* @retval Time
*/
/* lwIP timeout clock uses the same HAL millisecond counter. */
u32_t sys_now(void)
{
  return HAL_GetTick();
}

/* USER CODE END 6 */

/**
  * @brief  This function sets the netif link status.
  * @param  netif: the network interface
  * @retval None
  */
/* Link task polls PHY_BSR every 200 ms and changes the lwIP link flag.
 * PHY reads are checked; link changes are marshalled into tcpip_thread.
 */
void ethernetif_set_link(void const *argument)

{
  uint32_t regvalue = 0;
  struct link_str *link_arg = (struct link_str *)argument;

  for(;;)
  {
    /* Read PHY_BSR*/
    /* BSR link status may be latch-low. Read twice; ignore failed MDIO reads. */
    if (HAL_ETH_ReadPHYRegister(&heth, PHY_BSR, &regvalue) != HAL_OK ||
        HAL_ETH_ReadPHYRegister(&heth, PHY_BSR, &regvalue) != HAL_OK)
    {
      osDelay(200);
      continue;
    }

    regvalue &= PHY_LINKED_STATUS;

    /* Check whether the netif link down and the PHY link is up */
    if(!netif_is_link_up(link_arg->netif) && (regvalue))
    {
      /* network cable is connected */
      netifapi_netif_set_link_up(link_arg->netif);
    }
    else if(netif_is_link_up(link_arg->netif) && (!regvalue))
    {
      /* network cable is dis-connected */
      netifapi_netif_set_link_down(link_arg->netif);
    }

    /* Suspend thread for 200 ms */
    osDelay(200);
  }
}

/* USER CODE BEGIN 7 */

/* USER CODE END 7 */

#if LWIP_NETIF_LINK_CALLBACK
/**
  * @brief  Link callback function, this function is called on change of link status
  *         to update low level driver configuration.
* @param  netif: The network interface
  * @retval None
  */
/* Link-change callback: auto-negotiate (up to 1000 ms), configure speed/duplex
 * and restart MAC on link-up; stop MAC on link-down. Existing fallback is retained.
 */
void ethernetif_update_config(struct netif *netif)
{
  __IO uint32_t tickstart = 0;
  uint32_t regvalue = 0;

  if(netif_is_link_up(netif))
  {
    /* Restart the auto-negotiation */
    if(heth.Init.AutoNegotiation != ETH_AUTONEGOTIATION_DISABLE)
    {
      /* Enable Auto-Negotiation */
      HAL_ETH_WritePHYRegister(&heth, PHY_BCR, PHY_AUTONEGOTIATION);

      /* Get tick */
      tickstart = HAL_GetTick();

      /* Wait until the auto-negotiation will be completed */
      do
      {
        HAL_ETH_ReadPHYRegister(&heth, PHY_BSR, &regvalue);

        /* Check for the Timeout ( 1s ) */
        if((HAL_GetTick() - tickstart ) > 1000)
        {
          /* In case of timeout */
          goto error;
        }
      } while (((regvalue & PHY_AUTONEGO_COMPLETE) != PHY_AUTONEGO_COMPLETE));

      /* Read the result of the auto-negotiation */
      HAL_ETH_ReadPHYRegister(&heth, PHY_SR, &regvalue);

      /* Configure the MAC with the Duplex Mode fixed by the auto-negotiation process */
      if((regvalue & PHY_DUPLEX_STATUS) != (uint32_t)RESET)
      {
        /* Set Ethernet duplex mode to Full-duplex following the auto-negotiation */
        heth.Init.DuplexMode = ETH_MODE_FULLDUPLEX;
      }
      else
      {
        /* Set Ethernet duplex mode to Half-duplex following the auto-negotiation */
        heth.Init.DuplexMode = ETH_MODE_HALFDUPLEX;
      }
      /* Configure the MAC with the speed fixed by the auto-negotiation process */
      if(regvalue & PHY_SPEED_STATUS)
      {
        /* Set Ethernet speed to 10M following the auto-negotiation */
        heth.Init.Speed = ETH_SPEED_10M;
      }
      else
      {
        /* Set Ethernet speed to 100M following the auto-negotiation */
        heth.Init.Speed = ETH_SPEED_100M;
      }
    }
    else /* AutoNegotiation Disable */
    {
    error :
      /* Check parameters */
      assert_param(IS_ETH_SPEED(heth.Init.Speed));
      assert_param(IS_ETH_DUPLEX_MODE(heth.Init.DuplexMode));

      /* Set MAC Speed and Duplex Mode to PHY */
      HAL_ETH_WritePHYRegister(&heth, PHY_BCR, ((uint16_t)(heth.Init.DuplexMode >> 3) |
                                                     (uint16_t)(heth.Init.Speed >> 1)));
    }

    /* ETHERNET MAC Re-Configuration */
    HAL_ETH_ConfigMAC(&heth, (ETH_MACInitTypeDef *) NULL);

    /* Restart MAC interface */
    eth_start_result = (uint32_t)HAL_ETH_Start(&heth);
  }
  else
  {
    /* Stop MAC interface */
    HAL_ETH_Stop(&heth);
  }

  ethernetif_notify_conn_changed(netif);
}

/* USER CODE BEGIN 8 */
/**
  * @brief  This function notify user about link status changement.
  * @param  netif: the network interface
  * @retval None
  */
/* Optional application hook; the current weak implementation has no side effects. */
__weak void ethernetif_notify_conn_changed(struct netif *netif)
{
  /* NOTE : This is function could be implemented in user file
            when the callback is needed,
  */

}
/* USER CODE END 8 */
#endif /* LWIP_NETIF_LINK_CALLBACK */

/* USER CODE BEGIN 9 */
/* Transmit one complete Ethernet frame (without FCS) from task context, e.g. a raw
 * ARP probe. Shares the Tx descriptor ring with lwIP, so it takes the lwIP core
 * lock; never call it from tcpip_thread or an lwIP callback. Waits up to wait_ms
 * for a free descriptor. Returns 0 on success, -1 ring busy, -2 link down, -3 bad
 * length. A returned error means the frame was NOT queued. */
int ethernetif_send_raw(const uint8_t *frame, uint16_t length, uint32_t wait_ms)
{
  uint32_t start = HAL_GetTick();

  if (frame == NULL || length < 14 || length > ETH_TX_BUF_SIZE)
  {
    return -3;
  }
  for (;;)
  {
    if (!netif_is_link_up(&gnetif))
    {
      return -2;
    }
    LOCK_TCPIP_CORE();
    if ((heth.TxDesc->Status & ETH_DMATXDESC_OWN) == (uint32_t)RESET)
    {
      memcpy((uint8_t *)(heth.TxDesc->Buffer1Addr), frame, length);
      HAL_ETH_TransmitFrame(&heth, length);
      if ((heth.Instance->DMASR & ETH_DMASR_TUS) != (uint32_t)RESET)
      {
        heth.Instance->DMASR = ETH_DMASR_TUS;
        heth.Instance->DMATPDR = 0;
      }
      UNLOCK_TCPIP_CORE();
      return 0;
    }
    UNLOCK_TCPIP_CORE();
    if ((HAL_GetTick() - start) >= wait_ms)
    {
      return -1;
    }
    osDelay(1);
  }
}

/* MAC error counters for link diagnostics (CRC / alignment errors, frames missed
 * by the DMA). A rising CRC count with no good frames points to a speed/duplex
 * mismatch or a bad cable, not to a silent device. */
void ethernetif_read_counters(uint32_t *crc_errors, uint32_t *align_errors, uint32_t *missed)
{
  *crc_errors = ETH->MMCRFCECR;
  *align_errors = ETH->MMCRFAECR;
  *missed = ETH->DMAMFBOCR & 0xFFFFU;
}
/* USER CODE END 9 */
