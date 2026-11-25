"""Tests actual identity module with deterministic RTOS/lwIP test doubles.
No hardware, DHCP server, UART or real TCP stack is emulated.
Python 3 + GCC required. Bounds/UB checks on, leak detection off under ptrace.
"""
from pathlib import Path
import subprocess,tempfile,os,re
root=Path(__file__).resolve().parents[1]
header=(root/'Core/Inc/network_identity.h').read_text()
header=re.sub(r'^#include.*$','',header,flags=re.M)
source=(root/'Core/Src/network_identity.c').read_text()
source=re.sub(r'^#include.*$','',source,flags=re.M)
prefix=r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
typedef int err_t;typedef uint16_t u16_t;typedef int osStatus;typedef void *osMutexId;
typedef struct {uint32_t addr;} ip4_addr_t;
typedef ip4_addr_t ip_addr_t;
struct eth_addr {uint8_t addr[6];};
struct netif {ip4_addr_t ip,mask,gw;uint8_t hwaddr[6];unsigned up,link;};
struct netconn {ip_addr_t ip;uint16_t port;};
struct dhcp {unsigned state;};struct autoip {unsigned state;};
#define osMutexDef(x)
#define osMutex(x) 1
#define osWaitForever 0xffffffffU
#define osOK 0
#define ERR_OK 0
#define configASSERT(x) assert(x)
#define NETWORK_REGISTER_COUNT 64U
#define netif_ip4_addr(n) (&(n)->ip)
#define netif_ip4_netmask(n) (&(n)->mask)
#define netif_ip4_gw(n) (&(n)->gw)
#define netif_is_link_up(n) ((n)->link)
#define netif_is_up(n) ((n)->up)
#define ip4_addr_isany_val(x) ((x).addr==0)
#define ip4_addr_netcmp(a,b,m) (((a)->addr&(m)->addr)==((b)->addr&(m)->addr))
#define ip4_addr_cmp(a,b) ((a)->addr==(b)->addr)
#define IP_IS_V4(x) 1
#define ip_2_ip4(x) (x)
static unsigned clock_ms,lease,auto_lease,arp_available,locked;
static struct eth_addr cached_mac={{0,1,2,3,4,5}};
struct netif gnetif;
static uint32_t HAL_GetUIDw0(void){return 0x12345678;}
static uint32_t HAL_GetUIDw1(void){return 0x23456789;}
static uint32_t HAL_GetUIDw2(void){return 0x34567890;}
static uint32_t sys_now(void){return clock_ms;}
static size_t xPortGetFreeHeapSize(void){return 2000;}
static size_t xPortGetMinimumEverFreeHeapSize(void){return 1800;}
static osMutexId osMutexCreate(int n){assert(n==1);return (void*)1;}
static osStatus osMutexWait(osMutexId m,unsigned n){assert(m==(void*)1&&n==osWaitForever&&!locked);locked=1;return 0;}
static osStatus osMutexRelease(osMutexId m){assert(m==(void*)1&&locked);locked=0;return 0;}
static char *ip4addr_ntoa_r(const ip4_addr_t*ip,char*s,int n){const uint8_t*b=(const uint8_t*)&ip->addr;snprintf(s,n,"%u.%u.%u.%u",b[0],b[1],b[2],b[3]);return s;}
static void dhcp_set_struct(struct netif*n,struct dhcp*d){(void)n;d->state=0;}
static void autoip_set_struct(struct netif*n,struct autoip*d){(void)n;d->state=0;}
static int dhcp_start(struct netif*n){(void)n;return 0;}
static unsigned dhcp_supplied_address(struct netif*n){(void)n;return lease;}
static unsigned autoip_supplied_address(struct netif*n){(void)n;return auto_lease;}
static err_t netifapi_netif_common(struct netif*n,void(*f)(struct netif*),void*unused){assert(!unused);f(n);return 0;}
static int netifapi_dhcp_start(struct netif*n){return dhcp_start(n);}
static int netconn_getaddr(struct netconn*c,ip_addr_t*ip,u16_t*port,int local){assert(!local);*ip=c->ip;*port=c->port;return 0;}
static int etharp_find_addr(struct netif*n,const ip4_addr_t*ip,struct eth_addr**eth,const ip4_addr_t**found){(void)n;if(!arp_available)return -1;*eth=&cached_mac;*found=ip;return 0;}
static ip4_addr_t ip(unsigned a,unsigned b,unsigned c,unsigned d){uint8_t bytes[4]={a,b,c,d};ip4_addr_t v;memcpy(&v.addr,bytes,4);return v;}
'''
tests=r'''
int main(void){
 uint8_t mac[6],again[6],mask[4]={255,255,255,0},bad[4]={255,0,255,0};
 struct netconn c;uint16_t r[64];
 NetworkIdentity_MakeMAC(mac);NetworkIdentity_MakeMAC(again);
 assert(memcmp(mac,again,6)==0&&mac[0]==2);
 memcpy(gnetif.hwaddr,mac,6);gnetif.up=1;gnetif.link=1;
 NetworkIdentity_Start();assert(net_board_dbg.mode==0);
 assert(strcmp((const char*)net_client_dbg.ip,"unknown")==0);
 gnetif.ip=ip(172,18,8,100);gnetif.mask=ip(255,255,252,0);gnetif.gw=ip(172,18,8,1);lease=1;
 NetworkIdentity_Poll();assert(net_board_dbg.mode==1&&strcmp((const char*)net_board_dbg.ip,"172.18.8.100")==0);
 c.ip=ip(172,18,8,236);c.port=4444;arp_available=1;NetworkIdentity_ClientOpen(&c);
 assert(net_client_dbg.active==1&&net_client_dbg.mac_valid==1&&net_client_dbg.netmask_reported==0);
 assert(strcmp((const char*)net_client_dbg.mac,"00:01:02:03:04:05")==0);
 mask[2]=252;clock_ms=100;NetworkIdentity_Discovery(&c.ip,5555,mask);
 assert(net_client_dbg.netmask_reported==1&&strcmp((const char*)net_client_dbg.netmask,"255.255.252.0")==0);
 assert(NetworkIdentity_ReadRegisters(r));assert(r[0]==0x4e49&&r[2]==1&&r[16]==0xac12&&r[17]==0x08ec&&r[18]==0xffff&&r[19]==0xfc00&&r[23]==1&&r[24]==1);
 NetworkIdentity_Discovery(&c.ip,5555,bad);assert(net_client_dbg.netmask_reported==0);
 NetworkIdentity_Discovery(&c.ip,5555,NULL);assert(net_client_dbg.netmask_reported==0);
 NetworkIdentity_Discovery(&c.ip,5555,mask);clock_ms+=60001;NetworkIdentity_Poll();assert(net_client_dbg.netmask_reported==0);
 /* An off-subnet client has no observable endpoint MAC, even if a router ARP entry exists. */
 c.ip=ip(10,0,0,1);NetworkIdentity_ClientOpen(&c);assert(net_client_dbg.mac_valid==0);
 assert(NetworkIdentity_ReadRegisters(r)&&r[23]==0&&r[20]==0&&r[24]==0);
 c.ip=ip(172,18,8,236);NetworkIdentity_ClientOpen(&c);NetworkIdentity_Discovery(&c.ip,5555,mask);
 gnetif.link=0;NetworkIdentity_Poll();assert(net_client_dbg.mac_valid==0&&net_client_dbg.netmask_reported==0);
 gnetif.link=1;arp_available=0;NetworkIdentity_Poll();assert(net_client_dbg.mac_valid==0);
 NetworkIdentity_ClientClose();assert(!net_client_dbg.active);
 lease=0;auto_lease=1;gnetif.ip=ip(169,254,10,20);gnetif.mask=ip(255,255,0,0);NetworkIdentity_Poll();assert(net_board_dbg.mode==2);
 assert(!locked);puts("PASS: board modes, UID MAC, client IP, unknown MAC/mask, host report validation/expiry, routed peers and FC04 snapshot");
 return 0;}
'''
with tempfile.TemporaryDirectory() as d:
    path=Path(d)/'test.c';path.write_text(prefix+header+source+tests)
    exe=Path(d)/'identity'
    subprocess.run(['gcc','-std=c99','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g',str(path),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
