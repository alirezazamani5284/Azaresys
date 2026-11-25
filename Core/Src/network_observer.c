/* Observe frames before lwIP checks the destination subnet. No extra task/queue.
 * tcpip_inpkt transfers pbuf ownership only on ERR_OK, as tcpip_input does.
 */
#include "network_observer.h"
#include "ip_discovery.h"
#include "lwip/tcpip.h"
#include "netif/ethernet.h"
#include "lwip/sys.h"
#include <string.h>
volatile ObservedIdentity net_seen_dbg;
volatile ObservedIdentity net_neighbors_dbg[OBS_NEIGHBORS];
volatile uint32_t observer_frames, observer_events, observer_truncated;
static uint8_t capture[OBS_CAPTURE_BYTES];
static uint8_t addresses[OBS_NEIGHBORS][4];
static uint32_t mask_time[OBS_NEIGHBORS],binding_time[OBS_NEIGHBORS];
static uint8_t bound_macs[OBS_NEIGHBORS][6],view_macs[OBS_NEIGHBORS][6];
static unsigned last_slot;
static void text_ip(volatile char out[16],const uint8_t *bytes)
{
    ip4_addr_t a; char tmp[16]={0}; unsigned i;
    memcpy(&a.addr,bytes,4); ip4addr_ntoa_r(&a,tmp,16);
    for(i=0;i<16;i++) out[i]=tmp[i];
}
static void text_unknown(volatile char *out,unsigned n)
{ unsigned i; for(i=0;i<n;i++) out[i]=i<8?"unknown"[i]:0; }
static void record(const ObserverEvent *e)
{
    unsigned i,slot=0; uint32_t oldest=0,age,now=sys_now();
    volatile ObservedIdentity *v;
    for(i=0;i<OBS_NEIGHBORS;i++) {
        if(net_neighbors_dbg[i].valid && !memcmp(addresses[i],e->ip,4)) { slot=i; break; }
        if(!net_neighbors_dbg[i].valid) { slot=i; oldest=0xffffffffU; }
        else if(oldest!=0xffffffffU) { age=now-net_neighbors_dbg[i].last_seen_ms; if(age>=oldest) {oldest=age;slot=i;} }
    }
    v=&net_neighbors_dbg[slot];
    if(!v->valid || memcmp(addresses[slot],e->ip,4) ||
       (e->mac_is_host && memcmp(view_macs[slot],e->mac,6))) {
        memset((void*)v,0,sizeof(*v)); memcpy(addresses[slot],e->ip,4);
        text_unknown(v->netmask,16); text_unknown(v->gateway,16);
    }
    /* A weak IPv4 observation must not replace a stronger ARP/DHCP association. */
    if(e->mac_is_host || !v->mac_is_host || !v->fresh) {
        static const char h[]="0123456789ABCDEF";
        for(i=0;i<6;i++) {v->mac[3*i]=h[e->mac[i]>>4];v->mac[3*i+1]=h[e->mac[i]&15];if(i<5)v->mac[3*i+2]=':';}
        v->mac[17]=0; v->mac_is_host=e->mac_is_host;
        memcpy(view_macs[slot],e->mac,6);
    }
    if(e->mac_is_host) {memcpy(bound_macs[slot],e->mac,6);binding_time[slot]=now;}
    text_ip(v->ip,e->ip);
    if(e->mask_valid) {text_ip(v->netmask,e->mask);v->netmask_valid=1; mask_time[slot]=now;}
    if(e->gateway_valid) {text_ip(v->gateway,e->gateway);v->gateway_valid=1;mask_time[slot]=now;}
    v->source |= e->source; v->valid=1; v->fresh=1; v->last_seen_ms=now; v->age_ms=0; ++v->observations;
    last_slot=slot; net_seen_dbg=*v; ++observer_events;
}
static err_t receive_frame(struct pbuf *p,struct netif *n)
{
    ObserverEvent event; unsigned size=p->tot_len;
    ++observer_frames;
    if(size>sizeof(capture)) {size=sizeof(capture);++observer_truncated;}
    if(pbuf_copy_partial(p,capture,(u16_t)size,0)==size &&
       Observer_Parse(capture,size,p->tot_len,&event) &&
       memcmp(event.mac,n->hwaddr,6)!=0) {
        record(&event);
        if(event.discovery) IPDiscovery_Observe(n,&event);
    }
    return ethernet_input(p,n);
}
err_t NetworkObserver_Input(struct pbuf *p,struct netif *n)
{ return tcpip_inpkt(p,n,receive_frame); }
void NetworkObserver_Invalidate(void)
{
    unsigned i;
    for(i=0;i<OBS_NEIGHBORS;i++) {
        net_neighbors_dbg[i].fresh=0; net_neighbors_dbg[i].netmask_valid=0;
        net_neighbors_dbg[i].gateway_valid=0; net_neighbors_dbg[i].mac_is_host=0;
        net_neighbors_dbg[i].source=0;
    }
    net_seen_dbg.fresh=0;net_seen_dbg.netmask_valid=0;net_seen_dbg.gateway_valid=0;
    net_seen_dbg.mac_is_host=0;net_seen_dbg.source=0;
}
void NetworkObserver_Poll(struct netif *n)
{
    unsigned i; uint32_t now=sys_now();
    for(i=0;i<OBS_NEIGHBORS;i++) if(net_neighbors_dbg[i].valid) {
        net_neighbors_dbg[i].age_ms=now-net_neighbors_dbg[i].last_seen_ms;
        if(!netif_is_link_up(n) || net_neighbors_dbg[i].age_ms>60000U) net_neighbors_dbg[i].fresh=0;
        if(!net_neighbors_dbg[i].fresh || now-binding_time[i]>60000U) net_neighbors_dbg[i].mac_is_host=0;
        if(!net_neighbors_dbg[i].fresh || now-mask_time[i]>60000U) {
            net_neighbors_dbg[i].netmask_valid=0; net_neighbors_dbg[i].gateway_valid=0;
            text_unknown(net_neighbors_dbg[i].netmask,16); text_unknown(net_neighbors_dbg[i].gateway,16);
        }
    }
    if(net_neighbors_dbg[last_slot].valid) net_seen_dbg=net_neighbors_dbg[last_slot];
}

/* Extend the original 64-word FC04 bank with the latest observed endpoint. */
void NetworkObserver_ReadRegisters(uint16_t *r)
{
    unsigned i,count=0;ip4_addr_t ip;
    if(net_seen_dbg.valid) {
        for(i=0;i<2;i++) r[78+i]=(uint16_t)(((uint16_t)addresses[last_slot][2*i]<<8)|addresses[last_slot][2*i+1]);
        for(i=0;i<3;i++) r[80+i]=(uint16_t)(((uint16_t)view_macs[last_slot][2*i]<<8)|view_macs[last_slot][2*i+1]);
        if(net_seen_dbg.netmask_valid && ip4addr_aton((const char*)net_seen_dbg.netmask,&ip)) {
            const uint8_t *b=(const uint8_t*)&ip.addr;
            r[83]=(uint16_t)(((uint16_t)b[0]<<8)|b[1]);r[84]=(uint16_t)(((uint16_t)b[2]<<8)|b[3]);
        }
        if(net_seen_dbg.gateway_valid && ip4addr_aton((const char*)net_seen_dbg.gateway,&ip)) {
            const uint8_t *b=(const uint8_t*)&ip.addr;
            r[85]=(uint16_t)(((uint16_t)b[0]<<8)|b[1]);r[86]=(uint16_t)(((uint16_t)b[2]<<8)|b[3]);
        }
        r[87]=(uint16_t)(net_seen_dbg.last_seen_ms>>16);r[88]=(uint16_t)net_seen_dbg.last_seen_ms;
        r[89]=(uint16_t)(net_seen_dbg.observations>>16);r[90]=(uint16_t)net_seen_dbg.observations;
    }
    for(i=0;i<OBS_NEIGHBORS;i++) if(net_neighbors_dbg[i].valid&&net_neighbors_dbg[i].fresh) ++count;
    r[91]=(uint16_t)count;r[92]=OBS_CAPTURE_BYTES;
}
