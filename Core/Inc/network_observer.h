/* Bounded Ethernet observer. All state belongs to tcpip_thread. */
#ifndef NETWORK_OBSERVER_H
#define NETWORK_OBSERVER_H
#include <stdint.h>
#define OBS_NEIGHBORS 8U
#define OBS_CAPTURE_BYTES 640U
#define OBS_ARP 1U
#define OBS_IPV4 2U
#define OBS_DHCP_ACK 4U
#define OBS_DISCOVERY 8U
/* No authentication is implied by any of these observation sources. */
typedef struct {
    uint8_t ip[4], mac[6], mask[4], gateway[4], nonce[8], sender_ip[4], sender_mac[6];
    uint16_t port;
    uint8_t source, mask_valid, gateway_valid, mac_is_host, discovery;
} ObserverEvent;
typedef struct {
    char ip[16], mac[18], netmask[16], gateway[16];
    uint32_t valid, fresh, source, mac_is_host, netmask_valid, gateway_valid;
    uint32_t last_seen_ms, age_ms, observations;
} ObservedIdentity;
extern volatile ObservedIdentity net_seen_dbg;
extern volatile ObservedIdentity net_neighbors_dbg[OBS_NEIGHBORS];
extern volatile uint32_t observer_frames, observer_events, observer_truncated;
/* Pure parser: 1 = observation, 0 = unsupported/invalid. Never guesses a mask. */
int Observer_Parse(const uint8_t *frame, unsigned captured, unsigned wire_length,
                   ObserverEvent *event);
uint16_t Observer_Checksum(const uint8_t *bytes, unsigned length, uint32_t sum);
int Observer_ValidMask(const uint8_t mask[4]);
#ifndef OBSERVER_PARSER_ONLY
#include "lwip/netif.h"
#include "lwip/pbuf.h"
err_t NetworkObserver_Input(struct pbuf *p, struct netif *netif);
void NetworkObserver_Poll(struct netif *netif);
void NetworkObserver_Invalidate(void);
void NetworkObserver_ReadRegisters(uint16_t *registers);
#endif
#endif
