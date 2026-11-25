"""Compile the real bounded parser AND observer against a tiny pbuf/netif double."""
from pathlib import Path
import subprocess,tempfile,os
root=Path(__file__).resolve().parents[1]
source='\n'.join(x for x in (root/'Core/Src/network_observer.c').read_text().splitlines() if not x.startswith('#include'))
prefix=r'''
#define OBSERVER_PARSER_ONLY
#include "network_observer.h"
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
typedef uint16_t u16_t;typedef int err_t;
typedef struct {uint32_t addr;} ip4_addr_t;
struct netif {uint8_t hwaddr[6];unsigned link;};
struct pbuf {uint8_t *data;uint16_t tot_len;};
#define netif_is_link_up(n) ((n)->link)
static uint32_t clock_ms,delivered,probes;
static uint32_t sys_now(void){return clock_ms;}
static char *ip4addr_ntoa_r(const ip4_addr_t*a,char*s,int n){const uint8_t*p=(const uint8_t*)&a->addr;snprintf(s,n,"%u.%u.%u.%u",p[0],p[1],p[2],p[3]);return s;}
static int ip4addr_aton(const char*s,ip4_addr_t*a){unsigned x,y,z,w;uint8_t b[4];if(sscanf(s,"%u.%u.%u.%u",&x,&y,&z,&w)!=4)return 0;b[0]=x;b[1]=y;b[2]=z;b[3]=w;memcpy(&a->addr,b,4);return 1;}
static unsigned pbuf_copy_partial(struct pbuf*p,void*out,unsigned n,unsigned off){assert(n+off<=p->tot_len);memcpy(out,p->data+off,n);return n;}
static err_t ethernet_input(struct pbuf*p,struct netif*n){(void)p;(void)n;++delivered;return 0;}
static void IPDiscovery_Observe(struct netif*n,const ObserverEvent*e){(void)n;assert(e->discovery);++probes;}
static err_t tcpip_inpkt(struct pbuf*p,struct netif*n,err_t(*fn)(struct pbuf*,struct netif*)){return fn(p,n);}
'''
tests=r'''
static void w16(uint8_t*p,unsigned v){p[0]=(uint8_t)(v>>8);p[1]=(uint8_t)v;}
static unsigned arp(uint8_t*f){
 memset(f,0,700);memset(f,255,6);memcpy(f+6,"\x02\x11\x22\x33\x44\x55",6);
 w16(f+12,0x0806);w16(f+14,1);w16(f+16,0x0800);f[18]=6;f[19]=4;w16(f+20,1);
 memcpy(f+22,f+6,6);memcpy(f+28,"\xac\x21\x03\xa6",4);return 42;
}
static unsigned udp(uint8_t*f,unsigned payload,unsigned sport,unsigned dport){
 memset(f,0,700);memset(f,255,6);memcpy(f+6,"\x02\x11\x22\x33\x44\x55",6);w16(f+12,0x0800);
 f[14]=0x45;w16(f+16,28+payload);f[22]=64;f[23]=17;
 memcpy(f+26,"\xac\x21\x03\xa6",4);memset(f+30,255,4);
 w16(f+24,Observer_Checksum(f+14,20,0));w16(f+34,sport);w16(f+36,dport);w16(f+38,8+payload);
 return 42+payload;
}
int main(void){
 uint8_t f[700],badmask[4]={255,0,255,0};unsigned len,i,j;ObserverEvent e;
 struct netif net={{2,3,4,5,6,7},1};struct pbuf p;uint32_t rng=42;
 assert(!Observer_ValidMask(badmask));assert(Observer_ValidMask((const uint8_t*)"\xff\xff\xe0\0"));
 len=arp(f);assert(Observer_Parse(f,len,len,&e)&&e.source==OBS_ARP&&e.mac_is_host&&!e.mask_valid);
 for(i=0;i<42;i++)assert(!Observer_Parse(f,i,len,&e));
 f[22]=3;assert(!Observer_Parse(f,len,len,&e));f[22]=2;memset(f+28,0,4);assert(!Observer_Parse(f,len,len,&e));
 len=arp(f);p.data=f;p.tot_len=(uint16_t)len;assert(NetworkObserver_Input(&p,&net)==0);
 assert(net_seen_dbg.fresh&&net_seen_dbg.mac_is_host&&!net_seen_dbg.netmask_valid);
 assert(!strcmp((const char*)net_seen_dbg.ip,"172.33.3.166"));assert(delivered==1);
 /* Valid announcement reveals only the mask declared by the PC. */
 len=udp(f,20,54321,30303);memcpy(f+42,"F107FIND12345678",16);memcpy(f+58,"\xff\xff\xe0\0",4);
 assert(Observer_Parse(f,len,len,&e)&&e.discovery&&e.mask_valid&&!e.mac_is_host&&e.port==54321);
 p.tot_len=(uint16_t)len;NetworkObserver_Input(&p,&net);
 assert(probes==1&&net_seen_dbg.netmask_valid&&net_seen_dbg.mac_is_host);
 assert(!strcmp((const char*)net_seen_dbg.netmask,"255.255.224.0"));
 {uint16_t r[96]={0};NetworkObserver_ReadRegisters(r);assert(r[78]==0xac21&&r[79]==0x03a6&&r[83]==0xffff&&r[84]==0xe000&&r[91]==1);}
 /* A nonzero invalid UDP checksum must not produce a declaration. */
 f[40]=1;assert(!Observer_Parse(f,len,len,&e));f[40]=0;
 f[24]^=1;assert(!Observer_Parse(f,len,len,&e));
 /* Observe a valid DHCP ACK for another host; no authentication implied. */
 len=udp(f,256,67,68);f[42]=2;f[43]=1;f[44]=6;memcpy(f+58,"\xac\x21\x03\x55",4);
 memcpy(f+70,"\x02\xaa\xbb\xcc\xdd\xee",6);memcpy(f+278,"\x63\x82\x53\x63",4);
 memcpy(f+282,"\x35\x01\x05\x01\x04\xff\xff\xe0\x00\x03\x04\xac\x21\x00\x01\xff",16);
 assert(Observer_Parse(f,len,len,&e)&&e.source==OBS_DHCP_ACK&&e.mask_valid&&e.gateway_valid&&e.ip[3]==85&&e.mac[1]==0xaa);
 p.tot_len=(uint16_t)len;NetworkObserver_Input(&p,&net);assert(net_seen_dbg.mac_is_host&&net_seen_dbg.gateway_valid);
 f[286]=250;assert(!Observer_Parse(f,len,len,&e)); /* option exceeds packet */
 /* Truncated DHCP is at most an IP/L2 observation, never a DHCP lease. */
 assert(Observer_Parse(f,100,len,&e)&&e.source==OBS_IPV4&&!e.mask_valid);
 clock_ms=60001;NetworkObserver_Poll(&net);assert(!net_seen_dbg.fresh&&!net_seen_dbg.netmask_valid&&!net_seen_dbg.mac_is_host);
 len=arp(f);p.tot_len=(uint16_t)len;NetworkObserver_Input(&p,&net);NetworkObserver_Invalidate();NetworkObserver_Poll(&net);
 assert(!net_seen_dbg.fresh&&!net_seen_dbg.netmask_valid);
 /* Deterministic malformed-input corpus checks all length and alignment paths. */
 for(i=0;i<30000;i++) {
   rng=rng*1664525U+1013904223U;len=rng%700;
   for(j=0;j<len;j++){rng=rng*1664525U+1013904223U;f[j]=(uint8_t)(rng>>24);}
   Observer_Parse(f,len,len,&e);
 }
 puts("PASS: ARP, IPv4/router distinction, DHCP ACK/options, discovery, truncation, checksums, age/link invalidation and 30000 malformed frames");return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
    c=Path(d)/'observer.c';c.write_text(prefix+source+tests);exe=Path(d)/'observer'
    subprocess.run(['gcc','-std=c99','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g','-I'+str(root/'Core/Inc'),str(c),str(root/'Core/Src/network_observer_core.c'),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
