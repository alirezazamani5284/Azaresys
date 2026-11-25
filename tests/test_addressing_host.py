"""Run the project's REAL lwIP DHCP/AutoIP/ARP code with a fake NIC and clock.
The host harness is NO_SYS; target RTOS scheduling and the PHY are not simulated.
"""
from pathlib import Path
import subprocess,tempfile,os
root=Path(__file__).resolve().parents[1];lw=root/'Middlewares/Third_Party/LwIP/src'
opts='''
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_TCP 0
#define LWIP_IPV6 0
#define LWIP_DHCP 1
#define LWIP_AUTOIP 1
#define LWIP_DHCP_AUTOIP_COOP 1
#define LWIP_DHCP_AUTOIP_COOP_TRIES 1
#define LWIP_DHCP_CHECK_LINK_UP 1
#define DHCP_DOES_ARP_CHECK 1
#define MEM_SIZE 4096
#define MEM_ALIGNMENT 8
#define LWIP_STATS 0
'''
cc='''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#define LWIP_PLATFORM_DIAG(x) do {printf x;} while(0)
#define LWIP_PLATFORM_ASSERT(x) do {fprintf(stderr,"%s\\n",x);abort();} while(0)
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define LWIP_RAND() ((uint32_t)rand())
'''
code=r'''
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "lwip/prot/dhcp.h"
#include "lwip/prot/autoip.h"
#include "lwip/etharp.h"
#include "lwip/timeouts.h"
#include "lwip/inet_chksum.h"
#include "netif/ethernet.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static u32_t now_ms,tx;
u32_t sys_now(void){return now_ms;}
static err_t output(struct netif*n,struct pbuf*p){(void)n;(void)p;++tx;return ERR_OK;}
static err_t setup(struct netif*n){n->hwaddr_len=6;memcpy(n->hwaddr,"\x02\xaa\xbb\xcc\xdd\xee",6);n->mtu=1500;n->flags=NETIF_FLAG_BROADCAST|NETIF_FLAG_ETHARP;n->output=etharp_output;n->linkoutput=output;return ERR_OK;}
static void advance(unsigned ms){unsigned i;for(i=0;i<ms;i+=100){now_ms+=100;sys_check_timeouts();}}
static void w16(unsigned char*p,unsigned v){p[0]=(unsigned char)(v>>8);p[1]=(unsigned char)v;}
static void w32(unsigned char*p,u32_t v){p[0]=(unsigned char)(v>>24);p[1]=(unsigned char)(v>>16);p[2]=(unsigned char)(v>>8);p[3]=(unsigned char)v;}
static void reply(struct netif*n,unsigned kind){
 unsigned char f[342],*ip=f+14,*udp=f+34,*b=f+42;struct pbuf*p;unsigned short cs;unsigned pos=240;
 memset(f,0,sizeof(f));memcpy(f,n->hwaddr,6);memcpy(f+6,"\x02\x11\x22\x33\x44\x55",6);w16(f+12,0x800);
 ip[0]=0x45;w16(ip+2,328);ip[8]=64;ip[9]=17;memcpy(ip+12,"\xac\x21\x00\x01",4);memset(ip+16,255,4);
 cs=inet_chksum(ip,20);memcpy(ip+10,&cs,2);w16(udp,67);w16(udp+2,68);w16(udp+4,308);
 b[0]=2;b[1]=1;b[2]=6;w32(b+4,netif_dhcp_data(n)->xid);memcpy(b+16,"\xac\x21\x03\x55",4);memcpy(b+28,n->hwaddr,6);memcpy(b+236,"\x63\x82\x53\x63",4);
 b[pos++]=53;b[pos++]=1;b[pos++]=(unsigned char)kind;
 b[pos++]=54;b[pos++]=4;memcpy(b+pos,ip+12,4);pos+=4;
 b[pos++]=1;b[pos++]=4;memcpy(b+pos,"\xff\xff\xe0\0",4);pos+=4;
 b[pos++]=3;b[pos++]=4;memcpy(b+pos,ip+12,4);pos+=4;
 b[pos++]=51;b[pos++]=4;w32(b+pos,3600);pos+=4;b[pos++]=255;
 p=pbuf_alloc(PBUF_RAW,sizeof(f),PBUF_RAM);assert(p);assert(pbuf_take(p,f,sizeof(f))==ERR_OK);assert(ethernet_input(p,n)==ERR_OK);
}
int main(void){struct netif n;struct dhcp d;struct autoip a;ip4_addr_t zero;unsigned tx0;
 srand(7);lwip_init();ip4_addr_set_zero(&zero);assert(netif_add(&n,&zero,&zero,&zero,NULL,setup,ethernet_input));netif_set_default(&n);netif_set_up(&n);
 dhcp_set_struct(&n,&d);autoip_set_struct(&n,&a);assert(dhcp_start(&n)==ERR_OK);
 assert(!netif_is_link_up(&n)&&ip4_addr_isany_val(*netif_ip4_addr(&n)));
 netif_set_link_up(&n);assert(d.state==DHCP_STATE_SELECTING);assert(a.state!=AUTOIP_STATE_OFF);
 advance(12000);assert(autoip_supplied_address(&n)&&ip4_addr_islinklocal(netif_ip4_addr(&n)));assert(!dhcp_supplied_address(&n));
 tx0=tx;reply(&n,2);assert(d.state==DHCP_STATE_REQUESTING&&tx>tx0);
 reply(&n,5);advance(3000);assert(dhcp_supplied_address(&n)&&!autoip_supplied_address(&n));
 assert(!strcmp(ip4addr_ntoa(netif_ip4_addr(&n)),"172.33.3.85"));
 assert(!strcmp(ip4addr_ntoa(netif_ip4_netmask(&n)),"255.255.224.0"));
 netif_set_link_down(&n);assert(!netif_is_link_up(&n));netif_set_link_up(&n);assert(d.state==DHCP_STATE_REBOOTING);
 reply(&n,5);advance(3000);assert(dhcp_supplied_address(&n));
 dhcp_stop(&n);autoip_stop(&n);netif_remove(&n);
 puts("PASS: real lwIP DHCP waits for link, AutoIP fallback, DHCP offer/ACK and ARP check, /19 mask, link reconnect/reboot validation");return 0;}
'''
with tempfile.TemporaryDirectory() as d:
    path=Path(d);(path/'arch').mkdir();(path/'arch/cc.h').write_text(cc);(path/'lwipopts.h').write_text(opts);(path/'test.c').write_text(code)
    sources=[lw/'core'/f'{n}.c' for n in ['init','def','inet_chksum','ip','mem','memp','netif','pbuf','stats','sys','timeouts','udp','raw']]
    sources += [lw/'core/ipv4'/f'{n}.c' for n in ['autoip','dhcp','etharp','icmp','igmp','ip4','ip4_addr','ip4_frag']]+[lw/'netif/ethernet.c']
    exe=path/'addressing'
    subprocess.run(['gcc','-std=c99','-g','-fsanitize=address,undefined','-I'+str(path),'-I'+str(lw/'include'),str(path/'test.c'),*map(str,sources),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
