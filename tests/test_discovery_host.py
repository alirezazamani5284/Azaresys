from pathlib import Path
import subprocess
import tempfile
root=Path(__file__).resolve().parents[1]
source=(root/'Core/Src/ip_discovery.c').read_text()
body=source[source.index('static void write_u32'):source.index('static void discovery_entry')]
prefix=r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
typedef int err_t;
#define ERR_OK 0
#define ERR_MEM -1
#define REQUEST_SIZE 16U
#define RESPONSE_SIZE 60U
#define NULL_BUFFER 0
struct ip4 { uint32_t addr; };
typedef struct ip4 ip_addr_t;
struct netif { struct ip4 ip,mask; uint8_t hwaddr[6]; int up, link; };
struct netbuf { uint8_t *data; uint16_t size,port; ip_addr_t addr; };
struct netconn { int unused; };
#define netif_is_up(n) ((n)->up)
#define netif_is_link_up(n) ((n)->link)
#define netif_ip4_addr(n) (&((n)->ip))
#define netif_ip4_netmask(n) (&((n)->mask))
#define netbuf_fromport(n) ((n)->port)
#define netbuf_fromaddr(n) (&((n)->addr))
#define netbuf_len(n) ((n)->size)
#define ip_addr_copy(a,b) ((a)=(b))
static uint8_t response[60],interface_ready;
static uint32_t discovery_requests,discovery_replies;
static struct netif gnetif;
static unsigned int allocated, sent, fail_alloc;
static uint8_t captured[60];
static uint32_t HAL_GetUIDw0(void){return 0x12345678;}
static uint32_t HAL_GetUIDw1(void){return 0x90abcdef;}
static uint32_t HAL_GetUIDw2(void){return 0x10203040;}
static uint16_t netbuf_copy(struct netbuf *n,void *p,uint16_t size)
{assert(size<=n->size);memcpy(p,n->data,size);return size;}
static void netbuf_delete(struct netbuf *n){free(n->data);free(n);assert(allocated>0);--allocated;}
static struct netbuf *netbuf_new(void){struct netbuf*n;if(fail_alloc)return NULL;assert(allocated==0);n=calloc(1,sizeof(*n));assert(n);++allocated;return n;}
static void *netbuf_alloc(struct netbuf*n,uint16_t size){n->data=malloc(size);n->size=size;return n->data;}
static err_t netifapi_netif_common(struct netif*n,void(*f)(struct netif*),void *unused)
{(void)unused;f(n);return 0;}
static err_t netconn_sendto(struct netconn*c,struct netbuf*n,const ip_addr_t*a,uint16_t port)
{(void)c;assert(port==45678);assert(a->addr==0x0a0aa8c0);assert(n->size==60);memcpy(captured,n->data,60);++sent;return 0;}
static struct netbuf *incoming(unsigned size,int valid){struct netbuf*n=calloc(1,sizeof(*n));assert(n);++allocated;n->data=calloc(size+1,1);n->size=size;n->addr.addr=0x0a0aa8c0;n->port=45678;if(valid&&size>=16){memcpy(n->data,"F107FIND",8);memcpy(n->data+8,"12345678",8);}return n;}
'''
prefix += r'''
#define ip4_addr_isany_val(x) ((x).addr==0)
static unsigned reports, masks;
static void NetworkIdentity_Discovery(const ip_addr_t*peer,uint16_t port,const uint8_t*mask)
{assert(peer->addr==0x0a0aa8c0&&port==45678);++reports;if(mask)++masks;}
'''
tests=r'''
int main(void){struct netconn c={0};unsigned i;FILE*f;
gnetif.up=1;gnetif.link=1;gnetif.ip.addr=0x320aa8c0;gnetif.mask.addr=0x00ffffff;
memcpy(gnetif.hwaddr,"\x00\x80\xe1\x00\x00\x00",6);
assert(answer_request(&c,incoming(16,1))==0);assert(sent==1&&allocated==0);
assert(memcmp(captured,"F107HERE12345678",16)==0);
assert(captured[30]==1&&captured[31]==0xf6);
f=fopen("detector_build/response_fixture.bin","wb");assert(f);assert(fwrite(captured,1,60,f)==60);fclose(f);
for(i=0;i<65;i++){if(i==16||i==20)continue;assert(answer_request(&c,incoming(i,1))==0);assert(sent==1&&allocated==0);}
assert(answer_request(&c,incoming(16,0))==0);assert(sent==1&&allocated==0);
gnetif.link=0;assert(answer_request(&c,incoming(16,1))==0);assert(sent==1&&allocated==0);
gnetif.link=1;fail_alloc=1;assert(answer_request(&c,incoming(16,1))==ERR_MEM);assert(allocated==0);
fail_alloc=0;assert(answer_request(&c,incoming(16,1))==0);assert(sent==2&&allocated==0);
assert(answer_request(&c,incoming(20,1))==0);assert(sent==3&&masks==1&&allocated==0);
gnetif.ip.addr=0;assert(answer_request(&c,incoming(16,1))==0);assert(sent==3&&allocated==0);
return 0;}
'''
with tempfile.TemporaryDirectory() as d:
    fixture=str(Path(d)/'response.bin')
    c=Path(d)/'test.c';c.write_text(prefix+body+tests.replace('detector_build/response_fixture.bin',fixture))
    exe=Path(d)/'discovery'
    subprocess.run(['gcc','-std=c99','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,env={'ASAN_OPTIONS':'detect_leaks=0'})
print('PASS: legacy and extended discovery, no reply before address assignment, malformed packets, link down and allocation recovery')
