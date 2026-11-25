"""Actual Modbus parser, with network snapshot/send test doubles."""
from pathlib import Path
import subprocess,tempfile,os
root=Path(__file__).resolve().parents[1]
s=(root/'Core/Src/modbus_tcp.c').read_text()
body=s[s.index('static uint16_t read_u16'):s.index('/* Owns one accepted connection')]
prefix=r'''
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#define MODBUS_REGISTER_COUNT 16U
#define MODBUS_UNIT 1U
#define NETWORK_REGISTER_COUNT 64U
#define ERR_OK 0
#define ERR_VAL -6
#define ERR_TIMEOUT -3
#define NETCONN_COPY 1
typedef int err_t;typedef uint32_t u32_t;typedef int32_t s32_t;
struct netconn {int unused;};
static unsigned responses,fail_snapshot;
static uint8_t output[8][260];static size_t sizes[8];
static volatile uint16_t modbus_holding[16]={100,200,300};
static uint32_t modbus_requests,modbus_responses;
static uint32_t sys_now(void){return 0;}
#define netconn_set_sendtimeout(c,t) ((void)(c),(void)(t))
static int NetworkIdentity_ReadRegisters(uint16_t*r){unsigned i;if(fail_snapshot)return 0;for(i=0;i<64;i++)r[i]=(uint16_t)(1000+i);return 1;}
static err_t netconn_write_partly(struct netconn*c,const void*p,size_t n,int f,size_t*w){(void)c;assert(f==NETCONN_COPY);assert(responses<8);memcpy(output[responses],p,n);sizes[responses++]=n;*w=n;return 0;}
'''
tests=r'''
int main(void){
 uint8_t a[260],req[12]={0,1,0,0,0,6,1,3,0,0,0,3},joined[24];uint16_t used=0;unsigned i;
 struct netconn c={0};
 for(i=0;i<12;i++)assert(consume_bytes(&c,a,&used,req+i,1)==0);
 assert(!used&&responses==1&&sizes[0]==15&&read_u16(output[0]+9)==100&&read_u16(output[0]+13)==300);
 responses=0;req[7]=6;req[10]=0x12;req[11]=0x34;
 memcpy(joined,req,12);memcpy(joined+12,req,12);assert(consume_bytes(&c,a,&used,joined,24)==0&&responses==2&&modbus_holding[0]==0x1234);
 responses=0;req[7]=4;req[10]=0;req[11]=64;
 assert(consume_bytes(&c,a,&used,req,12)==0&&sizes[0]==137&&read_u16(output[0]+4)==131&&output[0][8]==128&&read_u16(output[0]+9)==1000&&read_u16(output[0]+135)==1063);
 responses=0;req[9]=63;req[11]=2;assert(consume_bytes(&c,a,&used,req,12)==0&&output[0][7]==0x84&&output[0][8]==2);
 responses=0;req[9]=0;req[11]=0;assert(consume_bytes(&c,a,&used,req,12)==0&&output[0][8]==3);
 responses=0;req[11]=1;fail_snapshot=1;assert(consume_bytes(&c,a,&used,req,12)==0&&output[0][8]==4);fail_snapshot=0;
 responses=0;req[7]=16;assert(consume_bytes(&c,a,&used,req,12)==0&&output[0][8]==1);
 responses=0;req[6]=2;assert(consume_bytes(&c,a,&used,req,12)==0&&responses==0);
 req[6]=1;req[2]=1;assert(consume_bytes(&c,a,&used,req,12)==ERR_VAL);used=0;
 req[2]=0;req[4]=1;assert(consume_bytes(&c,a,&used,req,12)==ERR_VAL);
 puts("PASS: FC03/06 preserved, FC04 bounds/snapshot failure, fragmented and coalesced ADUs, wrong unit and malformed MBAP");return 0;}
'''
with tempfile.TemporaryDirectory() as d:
    c=Path(d)/'test.c';c.write_text(prefix+body+tests);exe=Path(d)/'modbus'
    subprocess.run(['gcc','-std=c99','-Wall','-Wextra','-Werror','-g','-fsanitize=address,undefined',str(c),'-o',str(exe)],check=True)
    subprocess.run([str(exe)],check=True,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0'})
