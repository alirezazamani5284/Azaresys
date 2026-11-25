/* Host simulation of the whole scanner (Core/Src/mbscan.c) against modelled devices.
 * Fake RTOS with virtual time, fake lwIP raw TCP, fake ETH/PHY. One scenario per run. */
#include "mbscan.c"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

/* ---------------- globals required by the stubs ---------------- */
struct netif gnetif;
static ETH_TypeDef eth_regs;
ETH_HandleTypeDef heth = {&eth_regs, {ETH_MODE_FULLDUPLEX, ETH_SPEED_100M}};
void (* volatile ethernetif_rx_tap)(const uint8_t *, uint16_t);
volatile uint16_t ethernetif_vlan_id;

static uint32_t now_ms;
static jmp_buf done_jmp;
static int started_addressing;
static uint32_t board_ip_sim, board_mask_sim;
static int sem_count;
static uint32_t link_down_until;     /* 0 = none; else time the link comes back */
static uint32_t dev_link_t;          /* link-up time seen by the device */
static uint32_t probes_to_dev, probes_total;

typedef struct {
    const char *name;
    uint32_t ip, mask;
    uint8_t mac[6];
    int present;
    int probe_after_linkup;
    uint32_t boot_ms;
    int answers_probe0, answers_nonlocal, answers_all;
    int dhcp;
    int port502;            /* 1 open, 0 RST, -1 silent */
    int alt_port;           /* open Modbus port besides 502 (0 none) */
    int unit, unit_mode;    /* mode 0 only 'unit', 1 gateway (0x0B for others), 2 any unit */
    uint16_t vlan;
    /* expectations */
    int exp_found;
    uint32_t exp_ip, exp_board;
    int exp_modbus, exp_gateway, exp_unit;
    uint32_t exp_port, exp_conf, exp_tcp;
    uint32_t exp_methods;
    int exp_fail;
    const char *exp_vendor;
} Dev;

static Dev D;
static uint32_t cur_ip, cur_mask;
static int dhcp_state;              /* 0 none, 1 discover sent, 2 request sent, 3 bound */
static uint32_t dhcp_next, dhcp_offer_ip;
static unsigned ev_idx;
static uint32_t ev_t0;

/* ---------------- tiny frame helpers ---------------- */
static void wr16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }
static uint16_t r16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t r32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }

static void deliver(const uint8_t *f, uint16_t n)
{
    if (gnetif.link_up && ethernetif_rx_tap != NULL)
        ethernetif_rx_tap(f, n);
}

static void dev_arp(unsigned op, uint32_t spa, uint32_t tpa, const uint8_t *eth_dst)
{
    uint8_t f[128];
    uint16_t n = mbs_build_arp(f, D.vlan, eth_dst != NULL ? eth_dst : BCAST, D.mac, (uint16_t)op,
                               op == 2U ? gnetif.hwaddr : NULL, spa, tpa);
    deliver(f, n);
}

static void dev_udp_bootp(uint8_t type, uint32_t req_ip, uint32_t sid)
{
    uint8_t f[400], *ip = f + 14, *b = ip + 28, *o;
    memset(f, 0, sizeof f);
    memcpy(f, BCAST, 6); memcpy(f + 6, D.mac, 6); wr16(f + 12, 0x0800);
    ip[0] = 0x45; wr16(ip + 2, 28 + 300); ip[8] = 64; ip[9] = 17; wr32(ip + 12, 0); wr32(ip + 16, 0xFFFFFFFFUL);
    wr16(ip + 10, mbs_ip_checksum(ip, 20));
    wr16(ip + 20, 68); wr16(ip + 22, 67); wr16(ip + 24, 8 + 300);
    b[0] = 1; b[1] = 1; b[2] = 6; wr32(b + 4, 0x1234); wr16(b + 10, 0x8000); memcpy(b + 28, D.mac, 6);
    b[236] = 0x63; b[237] = 0x82; b[238] = 0x53; b[239] = 0x63;
    o = b + 240; *o++ = 53; *o++ = 1; *o++ = type;
    if (req_ip) { *o++ = 50; *o++ = 4; wr32(o, req_ip); o += 4; }
    if (sid) { *o++ = 54; *o++ = 4; wr32(o, sid); o += 4; }
    *o++ = 12; *o++ = 3; memcpy(o, "plc", 3); o += 3;
    *o++ = 255;
    deliver(f, 14 + 28 + 300);
}

/* device timeline, called every virtual millisecond */
static void dev_tick(void)
{
    uint32_t t;
    if (!D.present || !gnetif.link_up || ethernetif_rx_tap == NULL)
        return;
    t = now_ms;
    if (D.dhcp) {
        if (dhcp_state == 0 && t >= dev_link_t + D.boot_ms) { dev_udp_bootp(1, 0, 0); dhcp_state = 1; dhcp_next = t + 4000; }
        else if (dhcp_state == 1 && t >= dhcp_next) { dev_udp_bootp(1, 0, 0); dhcp_next = t + 4000; }
        if (dhcp_state == 3 && ev_idx == 0 && t >= dhcp_next) { dev_arp(1, 0, cur_ip, NULL); ev_idx = 1; dhcp_next = t + 1000; }
        else if (dhcp_state == 3 && ev_idx == 1 && t >= dhcp_next) { dev_arp(1, cur_ip, cur_ip, NULL); ev_idx = 2; }
        return;
    }
    if (!D.probe_after_linkup)
        return;
    {
        static const uint32_t off[5] = {0, 1200, 2400, 3600, 5600};
        if (ev_idx < 5U && t >= ev_t0 + D.boot_ms + off[ev_idx]) {
            if (ev_idx < 3U) dev_arp(1, 0, cur_ip, NULL);        /* RFC 5227 probe */
            else dev_arp(1, cur_ip, cur_ip, NULL);               /* announce */
            ++ev_idx;
        }
    }
}

static void dev_reset_sequence(void)
{
    ev_idx = 0;
    ev_t0 = now_ms;
    dev_link_t = now_ms;
    if (D.dhcp) { dhcp_state = 0; cur_ip = 0; }
}

/* ---------------- fake pending TCP events ---------------- */
typedef struct { uint32_t when; int type; struct tcp_pcb *pcb; uint8_t data[300]; uint16_t len; int used; } Ev;
static Ev evs[8];
static struct tcp_pcb pcbs[4];
static uint32_t pcb_dst; static uint16_t pcb_port; static int pcb_open;

static void ev_add(uint32_t delay, int type, struct tcp_pcb *p, const uint8_t *d, uint16_t n)
{
    unsigned i;
    for (i = 0; i < 8U; i++) if (!evs[i].used) {
        evs[i].used = 1; evs[i].when = now_ms + delay; evs[i].type = type; evs[i].pcb = p;
        evs[i].len = n; if (n) memcpy(evs[i].data, d, n);
        return;
    }
    abort();
}

static void ev_run(void)
{
    unsigned i;
    for (i = 0; i < 8U; i++) if (evs[i].used && evs[i].when <= now_ms) {
        Ev e = evs[i]; evs[i].used = 0;
        if (!e.pcb->in_use) continue;
        if (e.type == 1 && e.pcb->connected) e.pcb->connected(e.pcb->arg, e.pcb, ERR_OK);
        else if (e.type == 2) { e.pcb->in_use = 0; if (e.pcb->errf) e.pcb->errf(e.pcb->arg, ERR_RST); }
        else if (e.type == 3 && e.pcb->recv) {
            struct pbuf pb; pb.payload = e.data; pb.tot_len = e.len;
            e.pcb->recv(e.pcb->arg, e.pcb, &pb, ERR_OK);
        }
    }
}

static void sim_ms(void)
{
    ++now_ms;
    if (now_ms > 40000000UL) { puts("FAIL: virtual time limit"); exit(3); }
    if (link_down_until != 0U && now_ms >= link_down_until) {
        link_down_until = 0;
        gnetif.link_up = 1;
        ethernetif_notify_conn_changed(&gnetif);
        dev_reset_sequence();
    }
    dev_tick();
    ev_run();
}

/* ---------------- stub implementations ---------------- */
uint32_t HAL_GetTick(void) { return now_ms; }

void osDelay(uint32_t ms)
{
    while (ms--) sim_ms();
    if (mbscan_status.state == MBSCAN_ST_DONE || mbscan_status.state == MBSCAN_ST_FAILED)
        longjmp(done_jmp, 1);
}
osThreadId osThreadCreate(void *d, void *a) { (void)d; (void)a; return (osThreadId)1; }
osSemaphoreId osSemaphoreCreate(void *d, int c) { (void)d; sem_count = c; return (osSemaphoreId)1; }
int osSemaphoreRelease(osSemaphoreId s) { (void)s; sem_count = 1; return 0; }
int osSemaphoreWait(osSemaphoreId s, uint32_t timeout)
{
    (void)s;
    for (;;) {
        if (sem_count > 0) { sem_count = 0; return 1; }
        if (timeout == 0U) return 0;
        sim_ms();
        --timeout;
    }
}

int HAL_ETH_ReadPHYRegister(ETH_HandleTypeDef *h, uint16_t reg, uint32_t *v)
{
    (void)h;
    *v = reg == 4 ? 0x01E1U : reg == 5 ? 0x01E1U : reg == 6 ? 1U : 0U;
    return HAL_OK;
}

int HAL_ETH_WritePHYRegister(ETH_HandleTypeDef *h, uint16_t reg, uint32_t v)
{
    (void)h;
    if (reg == PHY_BCR) {
        if (v & PHY_POWERDOWN) { gnetif.link_up = 0; ethernetif_notify_conn_changed(&gnetif); }
        else if (v & PHY_RESTART_AUTONEGOTIATION) { link_down_until = now_ms + 1500; }
    }
    return HAL_OK;
}

err_t netifapi_netif_common(struct netif *n, netifapi_void_fn vf, netifapi_errt_fn ef) { if (vf) vf(n); if (ef) return ef(n); return ERR_OK; }
err_t netifapi_netif_set_addr(struct netif *n, const ip4_addr_t *ip, const ip4_addr_t *m, const ip4_addr_t *g)
{ (void)n; (void)g; board_ip_sim = ip->addr; board_mask_sim = m->addr; return ERR_OK; }
void dhcp_stop(struct netif *n) { (void)n; }
void autoip_stop(struct netif *n) { (void)n; }
u16_t pbuf_copy_partial(const struct pbuf *p, void *dst, u16_t len, u16_t off) { memcpy(dst, p->payload + off, len); return len; }
void pbuf_free(struct pbuf *p) { (void)p; }
void NetworkIdentity_StartAddressing(void) { started_addressing = 1; }
void ethernetif_read_counters(uint32_t *c, uint32_t *a, uint32_t *m) { *c = *a = *m = 0; }

struct tcp_pcb *tcp_new(void)
{
    unsigned i;
    for (i = 0; i < 4U; i++) if (!pcbs[i].in_use) { memset(&pcbs[i], 0, sizeof pcbs[i]); pcbs[i].in_use = 1; return &pcbs[i]; }
    return NULL;
}
void tcp_arg(struct tcp_pcb *p, void *a) { p->arg = a; }
void tcp_err(struct tcp_pcb *p, tcp_err_fn f) { p->errf = f; }
void tcp_recv(struct tcp_pcb *p, tcp_recv_fn f) { p->recv = f; }
void tcp_recved(struct tcp_pcb *p, u16_t l) { (void)p; (void)l; }
err_t tcp_close(struct tcp_pcb *p) { p->in_use = 0; return ERR_OK; }
void tcp_abort(struct tcp_pcb *p) { p->in_use = 0; }
err_t tcp_output(struct tcp_pcb *p) { (void)p; return ERR_OK; }

err_t tcp_connect(struct tcp_pcb *p, const ip_addr_t *ip, uint16_t port, tcp_connected_fn cb)
{
    int reach, openp;
    if (board_ip_sim == 0U || (board_ip_sim & board_mask_sim) != (ip->addr & board_mask_sim))
        return ERR_RTE;                                   /* lwIP: no route / not on-link */
    p->connected = cb;
    pcb_dst = ip->addr; pcb_port = port;
    reach = D.present && ip->addr == cur_ip && (board_ip_sim & D.mask) == (cur_ip & D.mask) && board_ip_sim != cur_ip;
    ++probes_to_dev;
    if (!reach) return ERR_OK;                           /* SYN goes unanswered */
    openp = (port == 502U && D.port502 == 1) || (D.alt_port != 0 && port == D.alt_port);
    if (port == 502U && D.port502 == -1) return ERR_OK;
    pcb_open = openp;
    ev_add(3, openp ? 1 : 2, p, NULL, 0);
    return ERR_OK;
}

err_t tcp_write(struct tcp_pcb *p, const void *data, u16_t len, uint8_t flags)
{
    const uint8_t *q = data; uint8_t r[64]; uint8_t unit; uint16_t n = 0;
    (void)flags;
    if (len < 8U || !pcb_open) return ERR_OK;
    unit = q[6];
    if (!(unit == D.unit || D.unit_mode == 2)) {
        if (D.unit_mode != 1) return ERR_OK;             /* silently ignored */
        memcpy(r, q, 2); wr16(r + 2, 0); wr16(r + 4, 3); r[6] = unit; r[7] = (uint8_t)(q[7] | 0x80); r[8] = 0x0B; n = 9;
    } else if (q[7] == 3) {
        memcpy(r, q, 2); wr16(r + 2, 0); wr16(r + 4, 5); r[6] = unit; r[7] = 3; r[8] = 2; r[9] = 0x12; r[10] = 0x34; n = 11;
    } else if (q[7] == 0x2B) {
        static const uint8_t body[] = {0x2B, 0x0E, 1, 0x81, 0, 0, 3, 0, 4, 'A', 'C', 'M', 'E', 1, 3, 'M', '-', '1', 2, 3, '1', '.', '0'};
        memcpy(r, q, 2); wr16(r + 2, 0); wr16(r + 4, 1 + sizeof body); r[6] = unit; memcpy(r + 7, body, sizeof body); n = 7 + sizeof body;
    }
    if (n) ev_add(4, 3, p, r, n);
    return ERR_OK;
}

/* raw frames sent by the scanner */
int ethernetif_send_raw(const uint8_t *f, uint16_t len, uint32_t wait)
{
    uint16_t p = 12, type;
    (void)wait;
    if (!gnetif.link_up) return -2;
    ++probes_total;
    type = r16(f + p);
    if (type == 0x8100) { p += 4; type = r16(f + p); }
    if (!D.present) return 0;
    if (type == 0x0806U && len >= p + 2U + 28U) {
        const uint8_t *a = f + p + 2;
        uint32_t spa = r32(a + 14), tpa = r32(a + 24);
        if (r16(a + 6) != 1U) return 0;
        if (D.answers_all || (cur_ip != 0U && tpa == cur_ip)) {
            int ok = 1;
            if (!D.answers_all) {
                if (spa == 0U) ok = D.answers_probe0;
                else if ((spa & D.mask) != (cur_ip & D.mask)) ok = D.answers_nonlocal;
            }
            if (ok) dev_arp(2, D.answers_all ? tpa : cur_ip, spa, gnetif.hwaddr);
        }
    } else if (type == 0x0800U && f[p + 2 + 9] == 17U) {
        const uint8_t *ip = f + p + 2, *b = ip + 28;
        if (r16(ip + 22) == 68U && b[0] == 2U && D.dhcp) {
            const uint8_t *o = b + 240; unsigned t = 0;
            while (*o != 255) { if (*o == 53) t = o[2]; o += 2 + o[1]; }
            if (t == 2U) { dhcp_offer_ip = r32(b + 16); dhcp_state = 2; dev_udp_bootp(3, dhcp_offer_ip, r32(b + 20)); }
            else if (t == 5U && dhcp_state == 2) {
                dhcp_state = 3; cur_ip = r32(b + 16); cur_mask = D.mask; ev_idx = 0; dhcp_next = now_ms + 500;
            }
        }
    }
    return 0;
}

/* ---------------- scenarios ---------------- */
#define MAC(x) {0x00, 0x1B, 0x2C, 0x3D, 0x4E, x}
static const Dev SC[] = {
 /* 1 */ {"static device announces itself after boot", MBS_IP(192,168,1,10), 0xFFFFFF00UL, MAC(1), 1, 1, 3000, 1,1,0, 0, 1, 0, 1,0, 0,
          1, MBS_IP(192,168,1,10), MBS_IP(192,168,1,9), 1,0,1, 502, 5, 1, 0, 0, "ACME"},
 /* 2 */ {"silent device found by ARP probe sweep (P3)", MBS_IP(10,0,1,77), 0xFFFFFF00UL, MAC(2), 1, 0, 0, 1,1,0, 0, 1, 0, 1,0, 0,
          1, MBS_IP(10,0,1,77), MBS_IP(10,0,1,78), 1,0,1, 502, 5, 1, MBS_SRC_ARP_REPLY, 0, "ACME"},
 /* 3 */ {"device ignoring sender 0.0.0.0 needs pass B", MBS_IP(192,168,0,33), 0xFFFFFF00UL, MAC(3), 1, 0, 0, 0,0,0, 0, 1, 0, 1,0, 0,
          1, MBS_IP(192,168,0,33), MBS_IP(192,168,0,34), 1,0,1, 502, 5, 1, MBS_SRC_ARP_REPLY, 0, "ACME"},
 /* 4 */ {"DHCP client gets the rescue lease", 0, 0xFFFFFF00UL, MAC(4), 1, 0, 1500, 1,1,0, 1, 1, 0, 1,0, 0,
          1, MBS_IP(192,168,50,100), MBS_IP(192,168,50,1), 1,0,1, 502, 5, 1, MBS_SRC_DHCP_LEASE, 0, "ACME"},
 /* 5 */ {"link-local device (169.254/16)", MBS_IP(169,254,77,200), 0xFFFF0000UL, MAC(5), 1, 0, 0, 1,1,0, 0, 1, 0, 1,0, 0,
          1, MBS_IP(169,254,77,200), MBS_IP(169,254,77,203), 1,0,1, 502, 5, 1, 0, 0, "ACME"},
 /* 6 */ {"device with /30 netmask", MBS_IP(192,168,1,10), 0xFFFFFFFCUL, MAC(6), 1, 0, 0, 1,1,0, 0, 1, 0, 1,0, 0,
          1, MBS_IP(192,168,1,10), MBS_IP(192,168,1,9), 1,0,1, 502, 5, 1, 0, 0, "ACME"},
 /* 7 */ {"port 502 closed (RST), host alive", MBS_IP(172,16,0,50), 0xFFFFFF00UL, MAC(7), 1, 0, 0, 1,1,0, 0, 0, 0, 1,0, 0,
          1, MBS_IP(172,16,0,50), MBS_IP(172,16,0,49), 0,0,0, 0, 3, 2, 0, 0, NULL},
 /* 8 */ {"Modbus on alternative port 5020", MBS_IP(172,16,1,60), 0xFFFFFF00UL, MAC(8), 1, 0, 0, 1,1,0, 0, 0, 5020, 1,0, 0,
          1, MBS_IP(172,16,1,60), MBS_IP(172,16,1,63), 1,0,1, 5020, 5, 2, 0, 0, "ACME"},
 /* 9 */ {"TCP->RTU gateway answers 0x0B for unit 1", MBS_IP(192,168,1,200), 0xFFFFFF00UL, MAC(9), 1, 1, 3000, 1,1,0, 0, 1, 0, 7,1, 0,
          1, MBS_IP(192,168,1,200), MBS_IP(192,168,1,203), 1,1,1, 502, 5, 1, 0, 0, NULL},
 /* 10 */ {"only unit 17 answers (unit scan)", MBS_IP(192,168,1,150), 0xFFFFFF00UL, MAC(10), 1, 1, 3000, 1,1,0, 0, 1, 0, 17,0, 0,
          1, MBS_IP(192,168,1,150), MBS_IP(192,168,1,149), 1,0,17, 502, 5, 1, 0, 0, "ACME"},
 /* 11 */ {"no device at all", 0, 0, MAC(11), 0, 0, 0, 0,0,0, 0, 0, 0, 0,0, 0,
          0, 0, 0, 0,0,0, 0, 0, 0, 0, 1, NULL},
 /* 12 */ {"VLAN tagged static device (VID 7)", MBS_IP(192,168,5,10), 0xFFFFFF00UL, MAC(12), 1, 1, 3000, 1,1,0, 0, 1, 0, 1,0, 7,
          1, MBS_IP(192,168,5,10), MBS_IP(192,168,5,9), 1,0,1, 502, 5, 1, 0, 0, "ACME"},
 /* 13 */ {"device answering every ARP (proxy)", MBS_IP(192,168,1,10), 0xFFFFFF00UL, MAC(13), 1, 0, 0, 1,1,1, 0, 1, 0, 1,0, 0,
          1, 0, 0, 0,0,0, 0, 0, 0, 0, 0, NULL},
};

int main(int argc, char **argv)
{
    int idx = argc > 1 ? atoi(argv[1]) : 1;
    int bad = 0;
    const MbScanDevice *d = &mbscan_result[0];
    uint32_t ip_found = 0;
    unsigned a, b, c, e;

    if (idx < 1 || idx > (int)(sizeof(SC) / sizeof(SC[0]))) return 2;
    D = SC[idx - 1];
    cur_ip = D.ip; cur_mask = D.mask;
    memcpy(gnetif.hwaddr, "\x02\x00\x00\x00\x00\x01", 6);
    gnetif.link_up = 1;                 /* cable already plugged at boot, like low_level_init */
    dev_reset_sequence();
    if (D.dhcp) cur_ip = 0;
    MbScan_Start();
    if (setjmp(done_jmp) == 0) scan_entry(NULL);

    printf("[%2d] %s\n     state=%u cycle=%u found=%u fail=%u elapsed=%us sent=%u drops=%u frames=%u vlan=%u wildcard=%u\n",
           idx, D.name, (unsigned)mbscan_status.state, (unsigned)mbscan_status.cycle, (unsigned)mbscan_status.found,
           (unsigned)mbscan_status.fail_reason, (unsigned)(mbscan_status.elapsed_ms / 1000), (unsigned)mbscan_status.probes_sent,
           (unsigned)mbscan_status.tx_drops, (unsigned)mbscan_status.frames_rx, (unsigned)mbscan_status.vlan_id,
           (unsigned)mbscan_status.wildcard);
    if (D.exp_fail) {
        if (mbscan_status.state != MBSCAN_ST_FAILED || !started_addressing || mbscan_status.fail_reason != MBSCAN_FAIL_NO_TRAFFIC) bad = 1;
        printf("     %s (fallback to DHCP=%d)\n", bad ? "MISMATCH" : "ok: failed as expected", started_addressing);
        return bad;
    }
    if (mbscan_status.state != MBSCAN_ST_DONE || mbscan_status.found < 1) { puts("     MISMATCH: nothing found"); return 1; }
    printf("     ip=%s mac=%s board=%s/%s conf=%u modbus=%u port=%u gw=%u units=%u(%u) arp=%u tcp=%u methods=0x%X vendor='%s' product='%s' rev='%s'\n",
           d->ip, d->mac, d->board_ip, d->board_mask, (unsigned)d->confidence, (unsigned)d->modbus_valid, (unsigned)d->port,
           (unsigned)d->gateway, (unsigned)d->unit_count, (unsigned)d->unit_ids[0], (unsigned)d->arp_alive,
           (unsigned)d->tcp_outcome, (unsigned)d->methods, d->vendor, d->product, d->revision);
    if (idx == 13) {
        if (!mbscan_status.wildcard) { puts("     MISMATCH: wildcard not flagged"); return 1; }
        puts("     ok: proxy-ARP peer detected, sweep stopped early");
        return 0;
    }
    if (sscanf(d->ip, "%u.%u.%u.%u", &a, &b, &c, &e) == 4) ip_found = MBS_IP(a, b, c, e);
    if (ip_found != D.exp_ip) { puts("     MISMATCH: ip"); bad = 1; }
    { char bs[16]; mbs_ip_str(bs, D.exp_board); if (strcmp(bs, d->board_ip)) { printf("     MISMATCH: board ip, expected %s\n", bs); bad = 1; } }
    if ((int)d->modbus_valid != D.exp_modbus || (int)d->gateway != D.exp_gateway) { puts("     MISMATCH: modbus/gateway"); bad = 1; }
    if (D.exp_modbus && ((int)d->unit_ids[0] != D.exp_unit || d->port != D.exp_port)) { puts("     MISMATCH: unit/port"); bad = 1; }
    if (d->confidence != D.exp_conf) { printf("     MISMATCH: confidence %u != %u\n", (unsigned)d->confidence, (unsigned)D.exp_conf); bad = 1; }
    if (D.exp_conf == 3U && d->tcp_outcome != D.exp_tcp) { puts("     MISMATCH: tcp outcome"); bad = 1; }
    if ((d->methods & D.exp_methods) != D.exp_methods) { puts("     MISMATCH: discovery method"); bad = 1; }
    if (D.exp_vendor && strcmp(d->vendor, D.exp_vendor)) { puts("     MISMATCH: vendor"); bad = 1; }
    if (D.vlan && mbscan_status.vlan_id != D.vlan) { puts("     MISMATCH: vlan"); bad = 1; }
    printf("     %s\n", bad ? "FAILED" : "ok");
    return bad;
}
