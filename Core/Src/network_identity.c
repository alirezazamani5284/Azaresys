/* Address management and peer identity.
 * All raw netif, DHCP, AutoIP and ARP access runs in tcpip_thread.
 * One mutex serializes callback arguments; volatile alone is not a lock.
 * No extra task is created. DHCP/AutoIP control blocks use static RAM.
 */
#include "network_identity.h"
#include "mbscan_config.h"
#include "main.h"
#include "FreeRTOS.h"
#include "task.h"
#include "cmsis_os.h"
#include "lwip/netifapi.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "lwip/etharp.h"
#include "lwip/sys.h"
#include <string.h>
extern struct netif gnetif;
volatile BoardIdentity net_board_dbg;
volatile PeerIdentity net_client_dbg;
volatile PeerIdentity net_discovery_dbg;
static struct dhcp dhcp_control;
static struct autoip autoip_control;
static osMutexId identity_mutex;
osMutexDef(NetworkIdentity);
static ip4_addr_t client_ip, discovery_ip, reported_mask;
static uint8_t have_client, have_discovery, have_reported_mask;
/* Protected callback arguments, never shared without identity_mutex. */
static ip4_addr_t argument_ip;
static uint8_t argument_mask[4];
static uint16_t argument_port;
static uint8_t argument_has_mask;
static uint16_t *register_destination;
static err_t addressing_status;
static void lock(void)
{
    osStatus status = osMutexWait(identity_mutex, osWaitForever);
    configASSERT(status == osOK);
}
static void unlock(void)
{
    osStatus status = osMutexRelease(identity_mutex);
    configASSERT(status == osOK);
}
static void ipv4_text(volatile char out[16], const ip4_addr_t *ip)
{
    char text[16] = {0}; unsigned i;
    ip4addr_ntoa_r(ip, text, sizeof(text));
    for (i=0;i<16;++i) out[i]=text[i];
}
static void unknown(volatile char *out, unsigned size)
{
    unsigned i; const char text[]="unknown";
    for(i=0;i<size;++i) out[i]= i<sizeof(text) ? text[i] : 0;
}
static void mac_text(volatile char out[18], const uint8_t *mac)
{
    static const char hex[]="0123456789ABCDEF"; unsigned i;
    for(i=0;i<6;++i) {
        out[3*i]=hex[mac[i]>>4];out[3*i+1]=hex[mac[i]&15];
        if(i<5)out[3*i+2]=':';
    }
    out[17]=0;
}
/* A locally administered unicast MAC derived from the complete UID.
 * Stable per MCU; not a guaranteed collision-free manufacturing allocation. */
void NetworkIdentity_MakeMAC(uint8_t mac[6])
{
    uint32_t words[3], a=2166136261UL, b=0x9e3779b9UL;
    unsigned i,j; uint8_t byte;
    words[0]=HAL_GetUIDw0();words[1]=HAL_GetUIDw1();words[2]=HAL_GetUIDw2();
    for(i=0;i<3;++i)for(j=0;j<4;++j) {
        byte=(uint8_t)(words[i]>>(8*j));
        a=(a^byte)*16777619UL;b=(b^byte)*2246822519UL;
    }
    mac[0]=0x02;mac[1]=(uint8_t)(a>>24);mac[2]=(uint8_t)(a>>16);
    mac[3]=(uint8_t)(a>>8);mac[4]=(uint8_t)a;mac[5]=(uint8_t)(b>>24);
}
/* Only report an ARP entry for the actual on-link peer. Never substitute
 * the router's MAC for the remote machine's MAC. No active ARP probe here. */
static const uint8_t *lookup_mac(struct netif *n, const ip4_addr_t *ip)
{
    struct eth_addr *eth; const ip4_addr_t *found;
    if(!netif_is_link_up(n) || ip4_addr_isany_val(*netif_ip4_addr(n)) ||
       !ip4_addr_netcmp(ip,netif_ip4_addr(n),netif_ip4_netmask(n))) return NULL;
    if(etharp_find_addr(n,ip,&eth,&found)<0)return NULL;
    return eth->addr;
}
static void refresh_peer(struct netif *n, volatile PeerIdentity *view,
                         const ip4_addr_t *ip, uint8_t present)
{
    const uint8_t *mac;
    view->ip_valid=present;
    if(!present) {unknown(view->mac,18);unknown(view->netmask,16);return;}
    ipv4_text(view->ip,ip);
    mac=lookup_mac(n,ip);view->mac_valid=(mac!=NULL);
    if(mac)mac_text(view->mac,mac);else unknown(view->mac,18);
    view->netmask_reported=have_reported_mask &&
                           ip4_addr_cmp(ip,&discovery_ip) && netif_is_link_up(n);
    if(view->netmask_reported)ipv4_text(view->netmask,&reported_mask);
    else unknown(view->netmask,16);
}
static void refresh(struct netif *n)
{
    ipv4_text(net_board_dbg.ip,netif_ip4_addr(n));
    ipv4_text(net_board_dbg.netmask,netif_ip4_netmask(n));
    ipv4_text(net_board_dbg.gateway,netif_ip4_gw(n));
    mac_text(net_board_dbg.mac,n->hwaddr);
    net_board_dbg.link_up=netif_is_link_up(n);
    net_board_dbg.interface_up=netif_is_up(n);
    net_board_dbg.dhcp_state=dhcp_control.state;
    net_board_dbg.autoip_state=autoip_control.state;
    net_board_dbg.mode=dhcp_supplied_address(n)?1U:(autoip_supplied_address(n)?2U:0U);
    /* A cable loss invalidates host-reported configuration; it may have changed. */
    if(!netif_is_link_up(n) || (have_discovery &&
       (uint32_t)(sys_now()-net_discovery_dbg.last_seen_ms)>60000U))
        have_reported_mask=0;
    refresh_peer(n,&net_client_dbg,&client_ip,have_client);
    refresh_peer(n,&net_discovery_dbg,&discovery_ip,have_discovery);
    ++net_board_dbg.updates;
}
static void start_addressing(struct netif *n)
{
    dhcp_set_struct(n,&dhcp_control);
    autoip_set_struct(n,&autoip_control);
#if !MBSCAN_ENABLE
    /* With the discovery scanner enabled the interface stays unaddressed until the
     * scan has finished; NetworkIdentity_StartAddressing() then restores DHCP. */
    addressing_status=dhcp_start(n);
#endif
    refresh(n);
}
void NetworkIdentity_Start(void)
{
    identity_mutex=osMutexCreate(osMutex(NetworkIdentity));
    configASSERT(identity_mutex!=NULL);
    unknown(net_client_dbg.ip,16);unknown(net_client_dbg.netmask,16);unknown(net_client_dbg.mac,18);
    unknown(net_discovery_dbg.ip,16);unknown(net_discovery_dbg.netmask,16);unknown(net_discovery_dbg.mac,18);
    net_board_dbg.status=netifapi_netif_common(&gnetif,start_addressing,NULL);
    if(net_board_dbg.status==ERR_OK)net_board_dbg.status=addressing_status;
}
void NetworkIdentity_StartAddressing(void)
{
    lock();
    addressing_status=netifapi_dhcp_start(&gnetif);
    unlock();
}
/* Poll is called by the existing default task, about once every 1.5 seconds. */
void NetworkIdentity_Poll(void)
{
    lock();
    /* Retry initial allocation/start failure, without creating another DHCP block. */
    if(addressing_status!=ERR_OK)addressing_status=netifapi_dhcp_start(&gnetif);
    net_board_dbg.status=netifapi_netif_common(&gnetif,refresh,NULL);
    if(net_board_dbg.status==ERR_OK)net_board_dbg.status=addressing_status;
    unlock();
}
static void opened(struct netif *n)
{
    client_ip=argument_ip;have_client=1;
    net_client_dbg.active=1;net_client_dbg.port=argument_port;
    net_client_dbg.last_seen_ms=sys_now();++net_client_dbg.observations;
    refresh(n);
}
void NetworkIdentity_ClientOpen(struct netconn *client)
{
    ip_addr_t ip;u16_t port;err_t status;
    status=netconn_getaddr(client,&ip,&port,0);
    lock();
    if(status==ERR_OK && IP_IS_V4(&ip)) {
        argument_ip=*ip_2_ip4(&ip);argument_port=port;
        netifapi_netif_common(&gnetif,opened,NULL);
    }
    unlock();
}
static void activity(struct netif *n)
{net_client_dbg.last_seen_ms=sys_now();refresh(n);}
void NetworkIdentity_ClientActivity(void)
{lock();netifapi_netif_common(&gnetif,activity,NULL);unlock();}
static void closed(struct netif *n)
{net_client_dbg.active=0;refresh(n);}
void NetworkIdentity_ClientClose(void)
{lock();netifapi_netif_common(&gnetif,closed,NULL);unlock();}
/* A mask is an OPTIONAL, UNAUTHENTICATED report by the discovery sender.
 * It cannot be inferred from the Modbus connection or from the peer's IP. */
static void announced(struct netif *n)
{
    uint32_t m, inverse;
    discovery_ip=argument_ip;have_discovery=1;have_reported_mask=0;
    net_discovery_dbg.port=argument_port;net_discovery_dbg.last_seen_ms=sys_now();
    ++net_discovery_dbg.observations;
    if(argument_has_mask) {
        m=((uint32_t)argument_mask[0]<<24)|((uint32_t)argument_mask[1]<<16)|
          ((uint32_t)argument_mask[2]<<8)|argument_mask[3];
        inverse=~m;
        if(m!=0 && inverse>=3 && (inverse&(inverse+1U))==0) {
            memcpy(&reported_mask.addr,argument_mask,4);have_reported_mask=1;
        }
    }
    refresh(n);
}
void NetworkIdentity_Discovery(const ip_addr_t *peer,uint16_t port,const uint8_t *mask)
{
    if(!IP_IS_V4(peer))return;
    lock();argument_ip=*ip_2_ip4(peer);argument_port=port;argument_has_mask=(mask!=NULL);
    if(mask)memcpy(argument_mask,mask,4);
    netifapi_netif_common(&gnetif,announced,NULL);unlock();
}
static void words(uint16_t *p,const uint8_t *b,unsigned n)
{unsigned i;for(i=0;i<n;++i)p[i]=(uint16_t)(((uint16_t)b[2*i]<<8)|b[2*i+1]);}
static void word32(uint16_t *p,uint32_t value)
{p[0]=(uint16_t)(value>>16);p[1]=(uint16_t)value;}
static void register_snapshot(struct netif *n)
{
    uint16_t *r=register_destination;const uint8_t *mac;
    refresh(n);memset(r,0,NETWORK_REGISTER_COUNT*sizeof(uint16_t));
    r[0]=0x4e49;r[1]=0x0100;r[2]=(uint16_t)net_board_dbg.mode;
    r[3]=(uint16_t)net_board_dbg.link_up;r[4]=(uint16_t)net_board_dbg.interface_up;
    r[5]=(uint16_t)net_client_dbg.active;
    words(r+6,(const uint8_t*)&netif_ip4_addr(n)->addr,2);
    words(r+8,(const uint8_t*)&netif_ip4_netmask(n)->addr,2);
    words(r+10,(const uint8_t*)&netif_ip4_gw(n)->addr,2);words(r+12,n->hwaddr,3);
    r[15]=have_client;
    if(have_client)words(r+16,(const uint8_t*)&client_ip.addr,2);
    if(net_client_dbg.netmask_reported)words(r+18,(const uint8_t*)&reported_mask.addr,2);
    mac=have_client?lookup_mac(n,&client_ip):NULL;
    if(mac)words(r+20,mac,3);
    r[23]=(mac!=NULL);r[24]=(uint16_t)net_client_dbg.netmask_reported;
    r[25]=(uint16_t)net_client_dbg.port;
    word32(r+26,net_client_dbg.last_seen_ms);word32(r+28,net_client_dbg.observations);
    r[30]=(uint16_t)net_board_dbg.dhcp_state;r[31]=(uint16_t)net_board_dbg.autoip_state;
    if(have_discovery)words(r+32,(const uint8_t*)&discovery_ip.addr,2);
    if(have_reported_mask)words(r+34,(const uint8_t*)&reported_mask.addr,2);
    r[36]=have_reported_mask;
    mac=have_discovery?lookup_mac(n,&discovery_ip):NULL;
    if(mac)words(r+37,mac,3);
    r[40]=(mac!=NULL);
    if(have_discovery)word32(r+41,sys_now()-net_discovery_dbg.last_seen_ms);
    if(have_client)word32(r+43,sys_now()-net_client_dbg.last_seen_ms);
    word32(r+45,(uint32_t)xPortGetFreeHeapSize());
    word32(r+47,(uint32_t)xPortGetMinimumEverFreeHeapSize());
}
int NetworkIdentity_ReadRegisters(uint16_t *destination)
{
    err_t status;
    lock();register_destination=destination;
    status=netifapi_netif_common(&gnetif,register_snapshot,NULL);
    register_destination=NULL;unlock();return status==ERR_OK;
}
