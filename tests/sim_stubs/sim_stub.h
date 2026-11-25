/* Host simulation stubs for Core/Src/mbscan.c: a fake RTOS, lwIP raw TCP, ETH MAC/PHY.
 * The device under test is modelled in tests/mbscan_sim.c. Single threaded, virtual time. */
#ifndef SIM_STUB_H
#define SIM_STUB_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef int8_t err_t;
typedef uint16_t u16_t;
typedef uint32_t u32_t;
#define ERR_OK 0
#define ERR_RST (-14)
#define ERR_CLSD (-12)
#define ERR_ABRT (-13)
#define ERR_MEM (-1)
#define ERR_RTE (-4)
#define TCP_WRITE_FLAG_COPY 1

/* --- HAL / ETH --- */
#define HAL_OK 0
typedef struct { uint32_t MACFFR; } ETH_TypeDef;
typedef struct { ETH_TypeDef *Instance; struct { uint32_t DuplexMode, Speed; } Init; } ETH_HandleTypeDef;
#define ETH_MACFFR_PM 0x1UL
#define ETH_MACFFR_PAM 0x10UL
#define ETH_MODE_FULLDUPLEX 0x800UL
#define ETH_SPEED_100M 0x4000UL
#define PHY_BCR 0
#define PHY_POWERDOWN 0x0800U
#define PHY_AUTONEGOTIATION 0x1000U
#define PHY_RESTART_AUTONEGOTIATION 0x0200U
uint32_t HAL_GetTick(void);
int HAL_ETH_ReadPHYRegister(ETH_HandleTypeDef *h, uint16_t reg, uint32_t *v);
int HAL_ETH_WritePHYRegister(ETH_HandleTypeDef *h, uint16_t reg, uint32_t v);

/* --- RTOS --- */
typedef void *osThreadId;
typedef void *osSemaphoreId;
#define osPriorityBelowNormal 0
#define osThreadDef(n, f, p, i, s) int os_thread_##n = 0
#define osThread(n) (&os_thread_##n)
#define osSemaphoreDef(n) int os_sem_##n = 0
#define osSemaphore(n) (&os_sem_##n)
void osDelay(uint32_t ms);
osThreadId osThreadCreate(void *def, void *arg);
osSemaphoreId osSemaphoreCreate(void *def, int count);
int osSemaphoreWait(osSemaphoreId s, uint32_t timeout_ms);
int osSemaphoreRelease(osSemaphoreId s);
#define taskENTER_CRITICAL() do {} while (0)
#define taskEXIT_CRITICAL() do {} while (0)

/* --- lwIP --- */
struct netif { uint8_t hwaddr[6]; int link_up; };
extern struct netif gnetif;
#define netif_is_link_up(n) ((n)->link_up)
typedef struct { uint32_t addr; } ip4_addr_t;
typedef ip4_addr_t ip_addr_t;
#define ip4_addr_set_u32(p, v) ((p)->addr = (v))
#define ip4_addr_set_zero(p) ((p)->addr = 0)
#define lwip_htonl(x) (x)
#define IP_ADDR4(p, a, b, c, d) ((p)->addr = ((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))
typedef void (*netifapi_void_fn)(struct netif *);
typedef err_t (*netifapi_errt_fn)(struct netif *);
err_t netifapi_netif_common(struct netif *n, netifapi_void_fn vf, netifapi_errt_fn ef);
err_t netifapi_netif_set_addr(struct netif *n, const ip4_addr_t *ip, const ip4_addr_t *mask, const ip4_addr_t *gw);
void dhcp_stop(struct netif *n);
void autoip_stop(struct netif *n);
#define LOCK_TCPIP_CORE() do {} while (0)
#define UNLOCK_TCPIP_CORE() do {} while (0)
struct pbuf { uint8_t *payload; u16_t tot_len; };
u16_t pbuf_copy_partial(const struct pbuf *p, void *dst, u16_t len, u16_t off);
void pbuf_free(struct pbuf *p);
struct tcp_pcb;
typedef err_t (*tcp_connected_fn)(void *arg, struct tcp_pcb *pcb, err_t err);
typedef err_t (*tcp_recv_fn)(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err);
typedef void (*tcp_err_fn)(void *arg, err_t err);
struct tcp_pcb { void *arg; tcp_connected_fn connected; tcp_recv_fn recv; tcp_err_fn errf; int in_use; };
struct tcp_pcb *tcp_new(void);
void tcp_arg(struct tcp_pcb *p, void *arg);
void tcp_err(struct tcp_pcb *p, tcp_err_fn f);
void tcp_recv(struct tcp_pcb *p, tcp_recv_fn f);
err_t tcp_connect(struct tcp_pcb *p, const ip_addr_t *ip, uint16_t port, tcp_connected_fn cb);
err_t tcp_write(struct tcp_pcb *p, const void *data, u16_t len, uint8_t flags);
err_t tcp_output(struct tcp_pcb *p);
void tcp_recved(struct tcp_pcb *p, u16_t len);
err_t tcp_close(struct tcp_pcb *p);
void tcp_abort(struct tcp_pcb *p);

/* --- ethernetif / identity hooks used by mbscan.c --- */
extern void (* volatile ethernetif_rx_tap)(const uint8_t *frame, uint16_t length);
extern volatile uint16_t ethernetif_vlan_id;
int ethernetif_send_raw(const uint8_t *frame, uint16_t length, uint32_t wait_ms);
void ethernetif_read_counters(uint32_t *crc, uint32_t *align, uint32_t *missed);
void ethernetif_notify_conn_changed(struct netif *netif);
void NetworkIdentity_StartAddressing(void);
extern ETH_HandleTypeDef heth;
#endif
