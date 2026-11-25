/* Portable frame parser: no RTOS, heap, pointers into DMA or unaligned loads. */
#define OBSERVER_PARSER_ONLY
#include "network_observer.h"
#include <string.h>
static uint16_t be16(const uint8_t *p)
{ return (uint16_t)(((uint16_t)p[0]<<8)|p[1]); }
uint16_t Observer_Checksum(const uint8_t *p,unsigned n,uint32_t sum)
{
    while(n>1U) { sum+=be16(p); p+=2; n-=2; }
    if(n) sum+=(uint32_t)p[0]<<8;
    while(sum>>16) sum=(sum&65535U)+(sum>>16);
    return (uint16_t)~sum;
}
static int valid_ip(const uint8_t *p)
{ return p[0]!=0 && p[0]!=127 && p[0]<224; }
static int valid_mac(const uint8_t *p)
{ return !(p[0]&1U) && (p[0]|p[1]|p[2]|p[3]|p[4]|p[5]); }
int Observer_ValidMask(const uint8_t p[4])
{
    uint32_t m=((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
    uint32_t inv=~m;
    /* Allow /1..32. /0 is not a usable directly attached host subnet. */
    return m!=0 && (inv&(inv+1U))==0;
}
int Observer_Parse(const uint8_t *f,unsigned n,unsigned wire,ObserverEvent *e)
{
    unsigned ihl,total,u,sport,dport,len,pos,opt,olen,kind=0,ended=0;
    const uint8_t *ip,*udp,*b;
    uint32_t sum;
    if(!f || !e || n<14 || wire<n || !valid_mac(f+6)) return 0;
    memset(e,0,sizeof(*e));
    if(be16(f+12)==0x0806U) {
        if(n<42 || be16(f+14)!=1 || be16(f+16)!=0x0800 || f[18]!=6 || f[19]!=4 ||
           (be16(f+20)!=1 && be16(f+20)!=2) || memcmp(f+6,f+22,6) || !valid_ip(f+28)) return 0;
        memcpy(e->ip,f+28,4); memcpy(e->mac,f+22,6);
        e->source=OBS_ARP; e->mac_is_host=1; return 1;
    }
    /* Tagged VLAN traffic is deliberately unsupported by this board profile. */
    if(be16(f+12)!=0x0800 || n<34) return 0;
    ip=f+14; ihl=(ip[0]&15U)*4U; total=be16(ip+2);
    if((ip[0]>>4)!=4 || ihl<20 || n<14+ihl || total<ihl || total>wire-14 ||
       Observer_Checksum(ip,ihl,0)!=0) return 0;
    if(valid_ip(ip+12)) {
        memcpy(e->ip,ip+12,4); memcpy(e->mac,f+6,6); e->source=OBS_IPV4;
        /* Ethernet source may be a router. Do not claim it is the remote host MAC. */
    }
    if(ip[9]!=17 || (be16(ip+6)&0xbfffU) || total<ihl+8 || n<14+ihl+8) return e->source!=0;
    udp=ip+ihl; u=be16(udp+4); sport=be16(udp); dport=be16(udp+2);
    if(u<8 || u!=total-ihl || n<14+ihl+u) return e->source!=0;
    /* IPv4 UDP checksum zero means omitted, as allowed by RFC 768. */
    if(be16(udp+6)) {
        sum=be16(ip+12)+be16(ip+14)+be16(ip+16)+be16(ip+18)+17U+u;
        if(Observer_Checksum(udp,u,sum)!=0) return 0;
    }
    b=udp+8; len=u-8;
    if(dport==30303U && sport && (len==16 || len==20) &&
       !memcmp(b,"F107FIND",8) && valid_ip(ip+12)) {
        e->source=OBS_DISCOVERY; e->discovery=1; e->port=(uint16_t)sport;
        memcpy(e->nonce,b+8,8); memcpy(e->sender_ip,ip+12,4); memcpy(e->sender_mac,f+6,6);
        /* Discovery can also be routed: MAC remains L2 sender, not proven host. */
        if(len==20 && Observer_ValidMask(b+16)) { memcpy(e->mask,b+16,4); e->mask_valid=1; }
        return 1;
    }
    if(sport!=67 || dport!=68 || len<241 || b[0]!=2 || b[1]!=1 || b[2]!=6 ||
       !valid_mac(b+28) || !valid_ip(b+16) || memcmp(b+236,"\x63\x82\x53\x63",4)) return e->source!=0;
    /* DHCP option overload is not interpreted; absence stays unknown. */
    pos=240;
    while(pos<len) {
        opt=b[pos++]; if(opt==255) { ended=1; break; } if(opt==0) continue;
        if(pos>=len) return 0;
        olen=b[pos++]; if(olen>len-pos) return 0;
        if(opt==53) { if(olen!=1 || kind) return 0; kind=b[pos]; }
        if(opt==1) {
            if(olen!=4 || e->mask_valid || !Observer_ValidMask(b+pos)) return 0;
            memcpy(e->mask,b+pos,4); e->mask_valid=1;
        }
        if(opt==3 && olen>=4 && (olen%4)==0 && valid_ip(b+pos)) {
            memcpy(e->gateway,b+pos,4); e->gateway_valid=1;
        }
        pos+=olen;
    }
    if(kind!=5 || !ended) { e->mask_valid=0; e->gateway_valid=0; return e->source!=0; }
    /* A DHCP ACK advertises a lease; observation is not proof of client acceptance. */
    memcpy(e->ip,b+16,4); memcpy(e->mac,b+28,6);
    e->source=OBS_DHCP_ACK; e->mac_is_host=1; return 1;
}
