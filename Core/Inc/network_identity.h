#ifndef NETWORK_IDENTITY_H
#define NETWORK_IDENTITY_H
#include "lwip/api.h"
#include <stdint.h>
#define NETWORK_REGISTER_COUNT 64U
/* Watch these separately: board identity is not the remote PC identity. */
typedef struct {
    char ip[16], netmask[16], gateway[16], mac[18];
    uint32_t mode, link_up, interface_up, dhcp_state, autoip_state;
    int32_t status;
    uint32_t updates;
} BoardIdentity;
typedef struct {
    char ip[16], netmask[16], mac[18];
    uint32_t ip_valid, mac_valid, netmask_reported, active;
    uint32_t port, last_seen_ms, observations;
} PeerIdentity;
extern volatile BoardIdentity net_board_dbg;
extern volatile PeerIdentity net_client_dbg; /* Last accepted Modbus connection. */
extern volatile PeerIdentity net_discovery_dbg; /* Last discovery sender. */
void NetworkIdentity_Start(void);
/* Start DHCP (then AutoIP) now. Used when the discovery scanner gives the interface back. */
void NetworkIdentity_StartAddressing(void);
void NetworkIdentity_Poll(void);
void NetworkIdentity_ClientOpen(struct netconn *client);
void NetworkIdentity_ClientActivity(void);
void NetworkIdentity_ClientClose(void);
void NetworkIdentity_Discovery(const ip_addr_t *peer, uint16_t port,
                               const uint8_t *reported_mask);
int NetworkIdentity_ReadRegisters(uint16_t *destination);
void NetworkIdentity_MakeMAC(uint8_t mac[6]);
#endif
