"""Test the actual link state transition function with MDIO/HAL test doubles."""
from pathlib import Path
import subprocess,tempfile,os
root=Path(__file__).resolve().parents[1];s=(root/'LWIP/Target/ethernetif.c').read_text()
body=s[s.index('void ethernetif_poll_link('):s.index('/* Compatibility entry point')]
a=s.index('void ethernetif_update_config(');b=s.index('/* USER CODE BEGIN 8 */',a);body+=s[a:b]
prefix=r'''
#include <stdint.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#define PHY_BSR 1
#define PHY_SR 16
#define PHY_LINKED_STATUS 4
#define PHY_AUTONEGO_COMPLETE 32
#define PHY_SPEED_STATUS 2
#define PHY_DUPLEX_STATUS 4
#define ETH_SPEED_10M 10
#define ETH_SPEED_100M 100
#define ETH_MODE_FULLDUPLEX 1
#define ETH_MODE_HALFDUPLEX 0
#define HAL_OK 0
struct netif {unsigned link;};
#define netif_is_link_up(n) ((n)->link)
struct handle {struct {unsigned Speed,DuplexMode;} Init;};
static struct handle heth;
static uint32_t eth_phy_errors,eth_phy_bsr,eth_phy_status,eth_speed_mbps,eth_full_duplex,eth_start_result,eth_link_changes;
static uint8_t phy_failures;
static unsigned bsr,status,read_fail,mac_fail,start_fail,reads,starts,stops,invalidations;
static int HAL_ETH_ReadPHYRegister(struct handle*h,unsigned reg,uint32_t*p){(void)h;++reads;*p=reg==PHY_BSR?bsr:status;return read_fail?1:0;}
static int HAL_ETH_ConfigMAC(struct handle*h,void*p){assert(h==&heth&&!p);return mac_fail?1:0;}
static int HAL_ETH_Start(struct handle*h){assert(h==&heth);++starts;return start_fail?1:0;}
static void HAL_ETH_Stop(struct handle*h){assert(h==&heth);++stops;}
static void NetworkObserver_Invalidate(void){++invalidations;}
static void ethernetif_notify_conn_changed(struct netif*n){(void)n;}
void ethernetif_update_config(struct netif*n);
static void netif_set_link_down(struct netif*n){n->link=0;ethernetif_update_config(n);}
static void netif_set_link_up(struct netif*n){n->link=1;ethernetif_update_config(n);}
'''
tests=r'''
int main(void){struct netif n={0};
 ethernetif_poll_link(&n);assert(!n.link&&!starts&&reads==2);
 bsr=4;status=1;ethernetif_poll_link(&n);assert(!n.link&&!starts);
 bsr=36;status=5;ethernetif_poll_link(&n);assert(n.link&&starts==1&&eth_speed_mbps==100&&eth_full_duplex==1);
 ethernetif_poll_link(&n);assert(starts==1&&eth_link_changes==1);
 bsr=0;ethernetif_poll_link(&n);assert(!n.link&&stops==1&&invalidations==2);
 bsr=36;status=3;mac_fail=1;ethernetif_poll_link(&n);assert(!n.link&&starts==1);
 mac_fail=0;start_fail=1;ethernetif_poll_link(&n);assert(!n.link);
 start_fail=0;ethernetif_poll_link(&n);assert(n.link&&eth_speed_mbps==10&&!eth_full_duplex);
 read_fail=1;ethernetif_poll_link(&n);ethernetif_poll_link(&n);assert(n.link);
 ethernetif_poll_link(&n);assert(!n.link&&stops==2);
 read_fail=0;ethernetif_poll_link(&n);assert(n.link&&!phy_failures);
 puts("PASS: cable absent/present, negotiation pending, 10/100 duplex decode, HAL failures, MDIO loss and reconnect");return 0;}
'''
with tempfile.TemporaryDirectory() as d:
    c=Path(d)/'link.c';c.write_text(prefix+body+tests);exe=Path(d)/'link'
    subprocess.run(['gcc','-std=c99','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
