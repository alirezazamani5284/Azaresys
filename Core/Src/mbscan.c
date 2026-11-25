/*
 * HYBRID MODBUS-TCP DEVICE IP DISCOVERY (firmware layer)
 * Algorithm stages and rationale: docs/MODBUS_SCAN_FA.md. Pure logic lives in
 * mbscan_core.c (host tested); this file connects it to lwIP, the ETH MAC/PHY
 * and FreeRTOS.
 *
 * Concurrency rules
 *  - mbs_rx_frame() runs only in the Ethernet input task (rx_tap), which has the
 *    highest priority. The scanner task reads/writes 'ctx' only inside
 *    taskENTER_CRITICAL sections, so both sides see consistent data.
 *  - Raw frames go through ethernetif_send_raw() (takes the lwIP core lock).
 *  - The TCP probe uses the lwIP raw API under LOCK_TCPIP_CORE(); its callbacks
 *    run in tcpip_thread and only copy data / set flags / give a semaphore.
 */

#include "mbscan.h"
#include "main.h"
#include "FreeRTOS.h"
#include "task.h"
#include "cmsis_os.h"
#include "ethernetif.h"
#include "network_identity.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"
#include "lwip/tcpip.h"
#include "lwip/tcp.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "lwip/pbuf.h"
#include <string.h>

extern struct netif gnetif;
extern ETH_HandleTypeDef heth;

/* ------------------------------------------------------------------------ */
/* debugger visible state                                                    */
/* ------------------------------------------------------------------------ */
MbScanStatus mbscan_status;
MbScanDevice mbscan_result[MBSCAN_MAX_RESULTS];
volatile uint32_t mbscan_cmd = 0;
volatile uint32_t mbscan_allow_p7 = MBSCAN_ALLOW_P7;

#if MBSCAN_ENABLE

#define R_FOUND   1
#define R_NONE    0
#define R_RESTART (-1)
#define R_DHCP    2

#define TCP_RX_MAX 300U

static const uint32_t vendor_defaults[] = { MBSCAN_VENDOR_DEFAULTS 0UL };
#define VENDOR_COUNT ((unsigned)(sizeof(vendor_defaults) / sizeof(vendor_defaults[0])) - 1U)

static const uint8_t BCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static MbsCtx ctx;              /* live evidence, single writer = rx_tap */
static MbsCtx snap;             /* scanner private copy */
static uint8_t txbuf[380];
static osThreadId scan_task;
static osSemaphoreId tcp_sem;
static volatile uint8_t tap_on;
static volatile uint32_t link_up_since;   /* tick of the last link-up (0 = never seen) */
static uint16_t tx_vlan;
static uint32_t scan_start_ms;
static uint32_t cycle_no;
static uint32_t crc0, align0, missed0;
static uint32_t pace_last, pace_budget;
static uint32_t rate_now;
static uint16_t mb_tid = 0x4D00U;
static uint8_t mb_rx[270];
static uint32_t dhcp_acks;
static uint32_t last_dhcp_seq;
static uint32_t result_board_ip[MBSCAN_MAX_RESULTS];
static uint32_t result_board_mask[MBSCAN_MAX_RESULTS];

/* ------------------------------------------------------------------------ */
/* shared context access                                                     */
/* ------------------------------------------------------------------------ */

static void rx_tap(const uint8_t *frame, uint16_t length)
{
    if (tap_on)
        (void)mbs_rx_frame(&ctx, frame, length, HAL_GetTick());
}

static void snapshot(void)
{
    taskENTER_CRITICAL();
    snap = ctx;
    taskEXIT_CRITICAL();
}

static unsigned ctx_self_count(void)
{
    unsigned n;
    taskENTER_CRITICAL();
    n = mbs_count_self(&ctx);
    taskEXIT_CRITICAL();
    return n;
}

static void ctx_reset(void)
{
    taskENTER_CRITICAL();
    mbs_ctx_reset_evidence(&ctx);
    taskEXIT_CRITICAL();
    last_dhcp_seq = 0;
}

static void ctx_set_solicit(uint8_t v)
{
    taskENTER_CRITICAL();
    ctx.solicit = v;
    if (v) { /* a new sweep round starts with a clean "answers everything" test */
        ctx.rep_n = 0;
        ctx.wildcard = 0;
    }
    taskEXIT_CRITICAL();
}

static void ctx_set_own_ip(uint32_t ip)
{
    taskENTER_CRITICAL();
    ctx.own_ip = ip;
    taskEXIT_CRITICAL();
}

static void ctx_note(uint32_t ip, const uint8_t *mac, uint8_t role, uint8_t conf, uint16_t src)
{
    taskENTER_CRITICAL();
    mbs_note(&ctx, ip, mac, role, conf, src, HAL_GetTick());
    taskEXIT_CRITICAL();
}

static const MbsEntry *snap_find(uint32_t ip, uint8_t role)
{
    unsigned i;
    for (i = 0; i < MBS_TABLE_SIZE; ++i)
        if (snap.e[i].used && snap.e[i].ip == ip && snap.e[i].role == role)
            return &snap.e[i];
    return NULL;
}

/* ------------------------------------------------------------------------ */
/* status publishing                                                         */
/* ------------------------------------------------------------------------ */

static void set_state(uint32_t state)
{
    mbscan_status.state = state;
    mbscan_status.elapsed_ms = HAL_GetTick() - scan_start_ms;
}

static void pub_status(void)
{
    mbscan_status.cycle = cycle_no;
    mbscan_status.elapsed_ms = HAL_GetTick() - scan_start_ms;
    mbscan_status.rate_pps = rate_now;
    mbscan_status.frames_rx = ctx.frames;
    mbscan_status.frames_bad = ctx.frames_bad;
    mbscan_status.arp_probes_seen = ctx.arp_probes_seen;
    mbscan_status.dhcp_client = ctx.dhcp_client;
    mbscan_status.wildcard = ctx.wildcard;
    mbscan_status.vlan_id = ctx.vlan_seen ? ctx.vlan_id : 0U;
    mbscan_status.dhcp_acks = dhcp_acks;
    if (ctx.peer_mac_valid)
        mbs_mac_str(mbscan_status.peer_mac, ctx.peer_mac);
    memcpy(mbscan_status.hostname, ctx.hostname, sizeof(mbscan_status.hostname));
    mbscan_status.link_age_ms = link_up_since != 0U ? HAL_GetTick() - link_up_since : 0U;
}

static void pub_counters(void)
{
    uint32_t c, a, m;
    ethernetif_read_counters(&c, &a, &m);
    mbscan_status.crc_errors = c - crc0;
    mbscan_status.align_errors = a - align0;
    mbscan_status.missed_frames = m - missed0;
}

static void pub_device(unsigned i, const MbScanDevice *d)
{
    if (i < MBSCAN_MAX_RESULTS) {
        mbscan_result[i] = *d;
        result_board_ip[i] = 0;
    }
}

/* ------------------------------------------------------------------------ */
/* link / PHY                                                                */
/* ------------------------------------------------------------------------ */

/* Strong override of the weak hook in ethernetif.c: called (tcpip_thread) after
 * every link change, after the MAC has been re-configured. HAL_ETH_ConfigMAC
 * resets the frame filter, so promiscuous mode must be re-applied here. */
static void apply_filter(int on)
{
    uint32_t v = heth.Instance->MACFFR;
    if (on)
        v |= (ETH_MACFFR_PM | ETH_MACFFR_PAM);
    else
        v &= ~(uint32_t)(ETH_MACFFR_PM | ETH_MACFFR_PAM);
    heth.Instance->MACFFR = v;
    (void)heth.Instance->MACFFR; /* write needs a readback delay (RM0008) */
}

void ethernetif_notify_conn_changed(struct netif *netif)
{
    if (netif_is_link_up(netif)) {
        link_up_since = HAL_GetTick();
        if (tap_on)
            apply_filter(1);
    } else {
        link_up_since = 0;
    }
}

static int phy_read(uint16_t reg, uint32_t *value)
{
    unsigned i;
    for (i = 0; i < 4U; ++i) { /* LinkThr shares MDIO: HAL_BUSY is retried */
        if (HAL_ETH_ReadPHYRegister(&heth, reg, value) == HAL_OK)
            return 1;
        osDelay(2);
    }
    return 0;
}

static int phy_write(uint16_t reg, uint32_t value)
{
    unsigned i;
    for (i = 0; i < 4U; ++i) {
        if (HAL_ETH_WritePHYRegister(&heth, reg, value) == HAL_OK)
            return 1;
        osDelay(2);
    }
    return 0;
}

/* PHY independent cross-check (IEEE 802.3 regs 4/5/6) of what auto-negotiation
 * resolved versus how the MAC was configured. Report only. */
static void phy_diag(void)
{
    uint32_t anar = 0, anlpar = 0, aner = 0, common;
    uint32_t mac_full, mac_100;
    uint32_t res_full = 0, res_100 = 0;
    mbscan_status.link_mismatch = 0;
    if (!netif_is_link_up(&gnetif) || !phy_read(4, &anar) || !phy_read(5, &anlpar) ||
        !phy_read(6, &aner))
        return;
    mac_full = (heth.Init.DuplexMode == ETH_MODE_FULLDUPLEX);
    mac_100 = (heth.Init.Speed == ETH_SPEED_100M);
    if (aner & 1U) { /* partner can auto-negotiate */
        common = anar & anlpar;
        if (common & 0x0100U) { res_full = 1; res_100 = 1; }
        else if (common & 0x0080U) { res_full = 0; res_100 = 1; }
        else if (common & 0x0040U) { res_full = 1; res_100 = 0; }
        else if (common & 0x0020U) { res_full = 0; res_100 = 0; }
        else return;
        if (res_full != mac_full || res_100 != mac_100)
            mbscan_status.link_mismatch = 1;
    } else if (mac_full) { /* parallel detection always means half duplex */
        mbscan_status.link_mismatch = 2;
    }
}

static int sleep_chk(uint32_t ms);

/* Drop the PHY link so the peer sees a real link-up and repeats its ARP probe /
 * announcement / DHCP sequence. Returns 1 when the link came back. */
static int phy_bounce(void)
{
    uint32_t t_b = HAL_GetTick(), t;
    (void)phy_write(PHY_BCR, PHY_POWERDOWN | PHY_AUTONEGOTIATION);
    osDelay(MBSCAN_BOUNCE_DOWN_MS);
    (void)phy_write(PHY_BCR, PHY_AUTONEGOTIATION | PHY_RESTART_AUTONEGOTIATION);
    t = HAL_GetTick();
    while ((HAL_GetTick() - t) < 8000U) {
        osDelay(50);
        if (netif_is_link_up(&gnetif) && link_up_since != 0U && link_up_since >= t_b)
            return 1;
    }
    return 0;
}

static int wait_link(uint32_t timeout_ms)
{
    uint32_t t0 = HAL_GetTick();
    set_state(MBSCAN_ST_WAIT_LINK);
    while (!netif_is_link_up(&gnetif)) {
        if ((HAL_GetTick() - t0) >= timeout_ms)
            return 0;
        osDelay(100);
        pub_status();
    }
    return 1;
}

/* ------------------------------------------------------------------------ */
/* lwIP address handling                                                     */
/* ------------------------------------------------------------------------ */

static void addressing_stop_cb(struct netif *n)
{
    dhcp_stop(n);
    autoip_stop(n);
}

static void apply_board(uint32_t ip, uint32_t mask)
{
    ip4_addr_t a, m, g;
    ip4_addr_set_u32(&a, lwip_htonl(ip));
    ip4_addr_set_u32(&m, lwip_htonl(mask));
    ip4_addr_set_zero(&g);
    (void)netifapi_netif_set_addr(&gnetif, &a, &m, &g);
    ctx_set_own_ip(ip);
}

/* ------------------------------------------------------------------------ */
/* raw transmit helpers                                                      */
/* ------------------------------------------------------------------------ */

static int tx_frame(uint16_t len)
{
    int rc = -3, tries;
    if (len == 0U) {
        ++mbscan_status.tx_drops;
        return rc;
    }
    for (tries = 0; tries < 3; ++tries) {
        rc = ethernetif_send_raw(txbuf, len, 4U);
        if (rc == 0) {
            ++mbscan_status.probes_sent;
            return 0;
        }
        if (rc == -2)
            break;
        osDelay(1);
    }
    ++mbscan_status.tx_drops;
    return rc;
}

static void send_arp(uint16_t op, uint32_t spa, uint32_t tpa)
{
    (void)tx_frame(mbs_build_arp(txbuf, tx_vlan, BCAST, gnetif.hwaddr, op, NULL, spa, tpa));
}

static void refresh_vlan(void)
{
    taskENTER_CRITICAL();
    tx_vlan = ctx.vlan_seen ? ctx.vlan_id : 0U;
    taskEXIT_CRITICAL();
}

/* ------------------------------------------------------------------------ */
/* waiting helpers                                                           */
/* ------------------------------------------------------------------------ */

/* 1 when the cycle must be abandoned: cable lost or a new scan was requested. */
static int must_abort(void)
{
    return !netif_is_link_up(&gnetif) || mbscan_cmd != 0U;
}

static int sleep_chk(uint32_t ms)
{
    uint32_t t0 = HAL_GetTick();
    while ((HAL_GetTick() - t0) < ms) {
        if (must_abort())
            return 1;
        osDelay(ms - (HAL_GetTick() - t0) > 20U ? 20U : 1U);
    }
    return must_abort();
}

/* sleep, but return 1 early when a SELF candidate showed up */
static int sleep_found(uint32_t ms)
{
    uint32_t t0 = HAL_GetTick();
    while ((HAL_GetTick() - t0) < ms) {
        if (ctx_self_count() != 0U)
            return 1;
        if (must_abort())
            return 0;
        osDelay(5);
    }
    return ctx_self_count() != 0U;
}

/* ------------------------------------------------------------------------ */
/* Stage 1: passive listening                                                */
/* ------------------------------------------------------------------------ */

static int stage_passive(uint32_t t0, uint32_t window_ms, uint32_t max_ms)
{
    uint32_t deadline = window_ms;
    set_state(MBSCAN_ST_PASSIVE);
    for (;;) {
        unsigned self;
        uint8_t dhcp, alive;
        if (sleep_chk(20))
            return R_RESTART;
        taskENTER_CRITICAL();
        self = mbs_count_self(&ctx);
        dhcp = ctx.dhcp_client;
        alive = ctx.peer_mac_valid;
        taskEXIT_CRITICAL();
        pub_status();
        if (self != 0U) {
            /* settle: a second address (alias, fallback) may follow immediately */
            if (sleep_chk(MBSCAN_SETTLE_MS))
                return R_RESTART;
            return R_FOUND;
        }
        if (dhcp)
            return R_DHCP;
        if ((HAL_GetTick() - t0) >= deadline) {
            /* the peer is talking (so it is alive) but has not told its address:
             * keep listening up to the extension limit (e.g. DHCP back-off) */
            if (alive && deadline < max_ms) {
                deadline += MBSCAN_T1_EXTEND_MS;
                if (deadline > max_ms)
                    deadline = max_ms;
                continue;
            }
            return R_NONE;
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Stage 2: DHCP rescue                                                      */
/* ------------------------------------------------------------------------ */

static int stage_dhcp(void)
{
    uint32_t t0 = HAL_GetTick(), acked_at = 0;
    int acked = 0;
    uint32_t seq_before;

    set_state(MBSCAN_ST_DHCP);
    apply_board(MBSCAN_DHCP_SERVER_IP, MBSCAN_DHCP_MASK);
    refresh_vlan();
    send_arp(1, MBSCAN_DHCP_SERVER_IP, MBSCAN_DHCP_SERVER_IP); /* announce */
    taskENTER_CRITICAL();
    seq_before = ctx.dhcp_seq;
    taskEXIT_CRITICAL();
    last_dhcp_seq = seq_before - 1U; /* answer the request that triggered this stage */

    while ((HAL_GetTick() - t0) < MBSCAN_DHCP_WINDOW_MS) {
        MbsDhcpReq rq;
        uint32_t seq;
        int type;
        if (sleep_chk(10)) {
            apply_board(0, 0);
            return R_RESTART;
        }
        taskENTER_CRITICAL();
        seq = ctx.dhcp_seq;
        rq = ctx.dhcp_req;
        taskEXIT_CRITICAL();
        if (seq != last_dhcp_seq) {
            last_dhcp_seq = seq;
            type = mbs_dhcp_decide(&rq, MBSCAN_DHCP_SERVER_IP, MBSCAN_DHCP_OFFER_IP);
            if (type != 0) {
                uint16_t n = mbs_dhcp_build_reply(txbuf, sizeof(txbuf), tx_vlan, &rq, type,
                                                  gnetif.hwaddr, MBSCAN_DHCP_SERVER_IP,
                                                  MBSCAN_DHCP_OFFER_IP, MBSCAN_DHCP_MASK,
                                                  MBSCAN_DHCP_LEASE_S);
                if (tx_frame(n) == 0 && type == MBS_DHCP_ACK) {
                    ctx_note(MBSCAN_DHCP_OFFER_IP, rq.chaddr, MBS_ROLE_SELF, MBS_CONF_ARP,
                             MBS_SRC_DHCP_LEASE);
                    ++dhcp_acks;
                    acked = 1;
                    acked_at = HAL_GetTick();
                }
            }
        }
        pub_status();
        if (acked && (HAL_GetTick() - acked_at) >= 250U)
            return R_FOUND;
        if (!acked && ctx_self_count() != 0U) { /* it fell back to a static/link-local IP */
            if (sleep_chk(MBSCAN_SETTLE_MS)) {
                apply_board(0, 0);
                return R_RESTART;
            }
            return R_FOUND;
        }
    }
    apply_board(0, 0); /* back to Stage 0 state */
    return R_NONE;
}

/* ------------------------------------------------------------------------ */
/* Stage 3: active ARP sweep                                                 */
/* ------------------------------------------------------------------------ */

static void pace_begin(uint32_t rate)
{
    rate_now = rate;
    pace_last = HAL_GetTick();
    pace_budget = 0;
}

static void pace(void)
{
    for (;;) {
        uint32_t now = HAL_GetTick();
        if (now != pace_last) {
            pace_budget += (now - pace_last) * rate_now;
            pace_last = now;
            if (pace_budget > rate_now * 10U) /* burst cap: 10 ms worth of frames */
                pace_budget = rate_now * 10U;
        }
        if (pace_budget >= 1000U) {
            pace_budget -= 1000U;
            return;
        }
        osDelay(1);
    }
}

/* Pass B sender: same /24, an address unlikely to be the peer's gateway or master. */
static uint32_t neighbour_sender(uint32_t candidate)
{
    uint32_t last = (candidate & 0xFFU) == 253U ? 252U : 253U;
    return (candidate & 0xFFFFFF00UL) | last;
}

static int sweep_group(unsigned group, int pass_b)
{
    MbsCand it;
    uint32_t hints[6];
    unsigned nh;
    unsigned round, rounds;
    uint32_t i, rot;

    taskENTER_CRITICAL();
    nh = mbs_collect_hints(&ctx, hints, 6);
    taskEXIT_CRITICAL();
    mbs_cand_build(&it, group, hints, nh, vendor_defaults, VENDOR_COUNT);
    if (it.total == 0U)
        return R_NONE;
    rounds = (it.total <= MBSCAN_SMALL_GROUP) ? 2U : 1U; /* ARP has no retransmit */
    rot = (it.total > 1U) ? (uint32_t)((cycle_no * 2654435761UL) % it.total) : 0U;
    mbscan_status.group = group;
    mbscan_status.group_total = it.total;
    mbscan_status.pass_b = (uint32_t)pass_b;
    refresh_vlan();

    for (round = 0; round < rounds; ++round) {
        uint32_t rate = round == 0U ? MBSCAN_RATE_PPS : MBSCAN_RATE_PPS / 2U;
        if (rate < MBSCAN_RATE_MIN_PPS)
            rate = MBSCAN_RATE_MIN_PPS;
        if (rate_now != 0U && rate_now < rate && round == 0U)
            rate = rate_now; /* keep a rate that already proved too fast */
        ctx_set_solicit(1);
        pace_begin(rate);
        for (i = 0; i < it.total; ++i) {
            uint32_t idx = (round & 1U) ? (it.total - 1U - i) : i;
            uint32_t ip;
            uint32_t drops_before = mbscan_status.tx_drops;
            idx = (uint32_t)(((uint64_t)idx + rot) % it.total);
            ip = mbs_cand_get(&it, idx);
            pace();
            send_arp(1, pass_b ? neighbour_sender(ip) : 0U, ip);
            if (mbscan_status.tx_drops != drops_before) { /* adaptive: back off after a drop */
                uint32_t slower = rate_now - rate_now / 4U;
                rate_now = slower < MBSCAN_RATE_MIN_PPS ? MBSCAN_RATE_MIN_PPS : slower;
            }
            if ((i & 15U) == 15U) {
                mbscan_status.group_done = i + 1U;
                if (must_abort()) {
                    ctx_set_solicit(0);
                    return R_RESTART;
                }
                if (ctx_self_count() != 0U) {
                    ctx_set_solicit(0);
                    if (sleep_chk(MBSCAN_DRAIN_MS))
                        return R_RESTART;
                    return R_FOUND;
                }
                if (ctx.wildcard) { /* one MAC answers everything: stop probing */
                    ctx_set_solicit(0);
                    if (sleep_chk(MBSCAN_DRAIN_MS))
                        return R_RESTART;
                    return ctx_self_count() != 0U ? R_FOUND : R_NONE;
                }
                if ((i & 255U) == 255U)
                    pub_status();
            }
        }
        mbscan_status.group_done = it.total;
        if (sleep_found(MBSCAN_GROUP_WAIT_MS)) { /* late replies */
            ctx_set_solicit(0);
            if (sleep_chk(MBSCAN_DRAIN_MS))
                return R_RESTART;
            return R_FOUND;
        }
        if (must_abort()) {
            ctx_set_solicit(0);
            return R_RESTART;
        }
    }
    ctx_set_solicit(0);
    return R_NONE;
}

static int run_groups(const uint8_t *groups, unsigned n, int pass_b)
{
    unsigned k;
    for (k = 0; k < n; ++k) {
        int r = sweep_group(groups[k], pass_b);
        if (r != R_NONE)
            return r;
    }
    return R_NONE;
}

static int stage_sweep(int full)
{
    static const uint8_t small_a[] = {0, 1, 2, 3, 4};
    static const uint8_t small_b[] = {0, 1, 2, 3, 4};
    static const uint8_t recheck[] = {0, 2, 3, 4};
    static const uint8_t big[] = {5, 6, 7};
    int r;

    set_state(MBSCAN_ST_SWEEP);
    rate_now = MBSCAN_RATE_PPS;
    if (!full) { /* later cycles: only the small groups, both passes */
        r = run_groups(recheck, sizeof(recheck), 0);
        if (r == R_NONE)
            r = run_groups(recheck, sizeof(recheck), 1);
        return r;
    }
    r = run_groups(small_a, sizeof(small_a), 0);          /* P0..P4, pass A */
    if (r == R_NONE)
        r = run_groups(small_b, sizeof(small_b), 1);      /* pass B only when A found nothing */
#if MBSCAN_SWEEP_P5_P6
    if (r == R_NONE)
        r = run_groups(big, mbscan_allow_p7 ? 3U : 2U, 0); /* P5, P6, P7 only if allowed */
#else
    if (r == R_NONE && mbscan_allow_p7)
        r = run_groups(&big[2], 1U, 0);
#endif
    return r;
}

/* ------------------------------------------------------------------------ */
/* TCP probe (lwIP raw API)                                                  */
/* ------------------------------------------------------------------------ */

typedef struct {
    struct tcp_pcb *pcb;
    volatile uint8_t alive;
    volatile uint8_t connected;
    volatile uint8_t failed;
    volatile uint8_t peer_closed;
    volatile err_t err;
    volatile uint16_t rx_len;
    uint8_t rx[TCP_RX_MAX];
} TcpProbe;

static TcpProbe tp;

static err_t cb_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)arg;
    (void)pcb;
    if (err == ERR_OK)
        tp.connected = 1;
    else
        tp.failed = 1;
    osSemaphoreRelease(tcp_sem);
    return ERR_OK;
}

static void cb_err(void *arg, err_t err) /* the pcb is already freed by lwIP */
{
    (void)arg;
    tp.alive = 0;
    tp.pcb = NULL;
    tp.failed = 1;
    tp.err = err;
    osSemaphoreRelease(tcp_sem);
}

static err_t cb_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    (void)arg;
    if (p == NULL) { /* remote FIN */
        tp.peer_closed = 1;
        osSemaphoreRelease(tcp_sem);
        return ERR_OK;
    }
    if (err == ERR_OK) {
        u16_t room = (u16_t)(TCP_RX_MAX - tp.rx_len);
        u16_t n = p->tot_len < room ? p->tot_len : room;
        if (n != 0U) {
            pbuf_copy_partial(p, &tp.rx[tp.rx_len], n, 0);
            tp.rx_len = (uint16_t)(tp.rx_len + n);
        }
        tcp_recved(pcb, p->tot_len);
    }
    pbuf_free(p);
    osSemaphoreRelease(tcp_sem);
    return ERR_OK;
}

static void sem_drain(void)
{
    while (osSemaphoreWait(tcp_sem, 0) == osOK)
    {
        /* Consume pending semaphore signals. */
    }
}

static void tcp_cleanup(void)
{
    LOCK_TCPIP_CORE();
    if (tp.alive && tp.pcb != NULL) {
        struct tcp_pcb *pcb = tp.pcb;
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_err(pcb, NULL);
        tcp_abort(pcb); /* sends RST, frees the pcb; callbacks were detached first */
    }
    tp.alive = 0;
    tp.pcb = NULL;
    UNLOCK_TCPIP_CORE();
}

static void tcp_end(void) /* graceful close of an established probe connection */
{
    LOCK_TCPIP_CORE();
    if (tp.alive && tp.pcb != NULL) {
        struct tcp_pcb *pcb = tp.pcb;
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_err(pcb, NULL);
        if (tcp_close(pcb) != ERR_OK)
            tcp_abort(pcb);
    }
    tp.alive = 0;
    tp.pcb = NULL;
    UNLOCK_TCPIP_CORE();
}

/* Connect to ip:port. Leaves the connection open on MBSCAN_TCP_OPEN. */
static uint32_t tcp_try(uint32_t ip, uint16_t port, uint32_t timeout_ms)
{
    struct tcp_pcb *pcb;
    ip_addr_t dst;
    err_t e;
    uint32_t t0;

    tcp_cleanup();
    sem_drain();
    LOCK_TCPIP_CORE();
    tp.connected = 0;
    tp.failed = 0;
    tp.peer_closed = 0;
    tp.err = ERR_OK;
    tp.rx_len = 0;
    pcb = tcp_new();
    if (pcb == NULL) {
        UNLOCK_TCPIP_CORE();
        return MBSCAN_TCP_ERROR;
    }
    tcp_arg(pcb, NULL);
    tcp_err(pcb, cb_err);
    tcp_recv(pcb, cb_recv);
    IP_ADDR4(&dst, (ip >> 24) & 0xFFU, (ip >> 16) & 0xFFU, (ip >> 8) & 0xFFU, ip & 0xFFU);
    tp.pcb = pcb;
    tp.alive = 1;
    e = tcp_connect(pcb, &dst, port, cb_connected);
    if (e != ERR_OK) {
        tp.alive = 0;
        tp.pcb = NULL;
        tcp_err(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_abort(pcb);
        UNLOCK_TCPIP_CORE();
        return MBSCAN_TCP_ERROR;
    }
    UNLOCK_TCPIP_CORE();

    t0 = HAL_GetTick();
    for (;;) {
        uint32_t used = HAL_GetTick() - t0;
        if (tp.connected)
            return MBSCAN_TCP_OPEN;
        if (tp.failed) {
            tcp_cleanup();
            return tp.err == ERR_RST ? MBSCAN_TCP_REFUSED : MBSCAN_TCP_ERROR;
        }
        if (used >= timeout_ms || must_abort()) {
            tcp_cleanup();
            return MBSCAN_TCP_TIMEOUT;
        }
        (void)osSemaphoreWait(tcp_sem, timeout_ms - used);
    }
}

static err_t tcp_send(const uint8_t *data, uint16_t len)
{
    err_t e = ERR_CLSD;
    LOCK_TCPIP_CORE();
    if (tp.alive && tp.pcb != NULL) {
        e = tcp_write(tp.pcb, data, len, TCP_WRITE_FLAG_COPY);
        if (e == ERR_OK)
            e = tcp_output(tp.pcb);
    }
    UNLOCK_TCPIP_CORE();
    return e;
}

static uint16_t probe_take(uint8_t *dst, uint16_t max)
{
    uint16_t n;
    LOCK_TCPIP_CORE();
    n = tp.rx_len < max ? tp.rx_len : max;
    if (n != 0U) {
        memcpy(dst, tp.rx, n);
        memmove(tp.rx, &tp.rx[n], (size_t)tp.rx_len - n);
        tp.rx_len = (uint16_t)(tp.rx_len - n);
    }
    UNLOCK_TCPIP_CORE();
    return n;
}

/* ------------------------------------------------------------------------ */
/* Modbus transactions                                                       */
/* ------------------------------------------------------------------------ */

#define MBT_OK      1
#define MBT_EXC     2
#define MBT_TIMEOUT 0
#define MBT_BAD     (-1)
#define MBT_CLOSED  (-2)

/* One request/response on the open probe connection. Stray bytes (e.g. a late
 * reply to an earlier request) are discarded and the wait continues. */
static int mb_txn(uint8_t unit, int devid, uint32_t timeout_ms, MbsMbInfo *info)
{
    uint8_t req[12];
    uint16_t rlen, got = 0, scratch;
    uint16_t tid = ++mb_tid;
    uint32_t t0 = HAL_GetTick();
    int bad_seen = 0;
    uint8_t flush[16];

    while ((scratch = probe_take(flush, sizeof(flush))) != 0U) {
    }
    rlen = devid ? mbs_mb_build_devid(req, tid, unit, 1, 0)
                 : mbs_mb_build_read(req, tid, unit, 3, 0, 1);
    if (tcp_send(req, rlen) != ERR_OK)
        return MBT_CLOSED;
    for (;;) {
        uint32_t used = HAL_GetTick() - t0;
        uint16_t n;
        int r;
        if (used >= timeout_ms || must_abort())
            return bad_seen ? MBT_BAD : MBT_TIMEOUT;
        (void)osSemaphoreWait(tcp_sem, timeout_ms - used);
        n = probe_take(mb_rx + got, (uint16_t)(sizeof(mb_rx) - got));
        got = (uint16_t)(got + n);
        r = devid ? mbs_mb_check_devid(mb_rx, got, tid, unit, info)
                  : mbs_mb_check_read(mb_rx, got, tid, unit, 3, 1, info);
        if (r == MBS_MB_OK)
            return MBT_OK;
        if (r == MBS_MB_EXCEPTION)
            return MBT_EXC;
        if (r == MBS_MB_INVALID) {
            bad_seen = 1;
            got = 0;
            continue;
        }
        if (tp.peer_closed && n == 0U && tp.rx_len == 0U)
            return MBT_CLOSED;
        if (got >= sizeof(mb_rx)) {
            bad_seen = 1;
            got = 0;
        }
    }
}

static void unit_found(MbScanDevice *d, uint8_t unit, const MbsMbInfo *info, int r)
{
    unsigned i;
    d->modbus_valid = 1;
    if (r == MBT_EXC && (info->exception == 0x0AU || info->exception == 0x0BU))
        d->gateway = 1; /* TCP->RTU gateway answering for a missing serial unit */
    for (i = 0; i < d->unit_count; ++i)
        if (d->unit_ids[i] == unit)
            return;
    if (d->unit_count < 4U)
        d->unit_ids[d->unit_count++] = unit;
}

/* Strict Modbus confirmation on the open connection (port already known). */
static void modbus_session(MbScanDevice *d, uint16_t port)
{
    static const uint8_t first_units[3] = {1, 0xFF, 0};
    MbsMbInfo info;
    unsigned k;
    int r;
    uint8_t unit_ok = 0;
    uint32_t t_budget;

    for (k = 0; k < 3U; ++k) {
        uint32_t to = (k == 0U || !d->modbus_valid) ? MBSCAN_MB_TIMEOUT_MS : 300U;
        r = mb_txn(first_units[k], 0, to, &info);
        if (r == MBT_OK || r == MBT_EXC) {
            if (!d->modbus_valid)
                unit_ok = first_units[k];
            unit_found(d, first_units[k], &info, r);
        } else if (r == MBT_CLOSED || (r == MBT_BAD && !d->modbus_valid)) {
            break; /* not Modbus, or the peer closed the connection */
        }
    }
    if (!d->modbus_valid && tp.alive && !tp.peer_closed) { /* low-rate unit ID scan 2..247 */
        t_budget = HAL_GetTick();
        for (k = 2; k <= 247U; ++k) {
            if ((HAL_GetTick() - t_budget) >= MBSCAN_UNIT_SCAN_BUDGET_MS)
                break;
            r = mb_txn((uint8_t)k, 0, MBSCAN_MB_SCAN_TIMEOUT_MS, &info);
            if (r == MBT_OK || r == MBT_EXC) {
                unit_ok = (uint8_t)k;
                unit_found(d, (uint8_t)k, &info, r);
                break;
            }
            if (r == MBT_CLOSED || r == MBT_BAD)
                break;
        }
    }
    if (d->modbus_valid) {
        d->port = port;
        d->confidence = MBS_CONF_MODBUS;
        /* optional: FC 0x2B / MEI 0x0E basic device identification */
        r = mb_txn(unit_ok != 0U ? unit_ok : d->unit_ids[0], 1, MBSCAN_MB_TIMEOUT_MS, &info);
        if (r == MBT_OK)
            mbs_mb_parse_devid(mb_rx, info.frame_len, d->vendor, sizeof(d->vendor),
                               d->product, sizeof(d->product), d->revision,
                               sizeof(d->revision));
    }
}

/* ------------------------------------------------------------------------ */
/* Stage 4: verification                                                     */
/* ------------------------------------------------------------------------ */

static int board_free(uint32_t board_ip, const MbsEntry *dev)
{
    const MbsEntry *e;
    uint8_t n;
    for (n = 0; n < 2U; ++n) {
        send_arp(1, 0U, board_ip); /* RFC 5227 probe */
        if (sleep_chk(MBSCAN_ARP_PROBE_WAIT_MS / 2U))
            return 0;
    }
    snapshot();
    if (snap.wildcard)
        return 1; /* proxy-ARP peers "own" every address: the test is meaningless */
    e = snap_find(board_ip, MBS_ROLE_SELF);
    return !(e != NULL && !(e->mac_valid && memcmp(e->mac, dev->mac, 6) == 0));
}

/* ARP request from the board's new address; true when the device answered. */
static int arp_resolve(const MbsEntry *dev, uint32_t board_ip)
{
    uint32_t t0 = HAL_GetTick();
    unsigned tries = 0;
    send_arp(1, board_ip, dev->ip);
    while ((HAL_GetTick() - t0) < MBSCAN_ARP_RESOLVE_MS) {
        const MbsEntry *e;
        if (sleep_chk(10))
            return 0;
        snapshot();
        e = snap_find(dev->ip, MBS_ROLE_SELF);
        if (e != NULL && e->last_ms >= t0 && (e->sources & MBS_SRC_ARP_SENDER))
            return 1;
        if (++tries == 15U)
            send_arp(1, board_ip, dev->ip); /* one retry */
    }
    return 0;
}

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    uint32_t methods;
    uint32_t conf;
    uint32_t board_ip;
    uint32_t board_mask;
} VerifyTarget;

/* TCP + Modbus on one port with the configured attempts. */
static uint32_t probe_port(MbScanDevice *d, uint32_t ip, uint16_t port)
{
    uint32_t r = MBSCAN_TCP_NONE;
    unsigned a;
    for (a = 0; a < MBSCAN_TCP_ATTEMPTS; ++a) {
        r = tcp_try(ip, port, MBSCAN_TCP_TIMEOUT_MS);
        if (r == MBSCAN_TCP_OPEN || r == MBSCAN_TCP_REFUSED || must_abort())
            break;
    }
    if (r == MBSCAN_TCP_OPEN) {
        if (port == 502U)
            d->port502_open = 1;
        if (d->confidence < MBS_CONF_TCP)
            d->confidence = MBS_CONF_TCP;
        modbus_session(d, port);
        tcp_end();
    } else if (r == MBSCAN_TCP_REFUSED && d->confidence < MBS_CONF_ARP) {
        d->confidence = MBS_CONF_ARP; /* it answered with a RST: reachable */
    }
    return r;
}

/* Verify one candidate. Returns 1 when a device record was produced. */
static int verify_candidate(const MbsEntry *e, MbScanDevice *d, VerifyTarget *vt)
{
    uint32_t boards[4], peers[MBS_TABLE_SIZE], mask, known_mask;
    unsigned nb, np = 0, bi, i;
    int lease = (e->sources & MBS_SRC_DHCP_LEASE) != 0U;
    int reached = 0;
    uint32_t r502 = MBSCAN_TCP_NONE;

    memset(d, 0, sizeof(*d));
    memset(vt, 0, sizeof(*vt));
    mbs_ip_str(d->ip, e->ip);
    if (e->mac_valid)
        mbs_mac_str(d->mac, e->mac);
    d->methods = e->sources;
    d->confidence = e->conf;
    vt->ip = e->ip;
    memcpy(vt->mac, e->mac, 6);

    snapshot();
    known_mask = snap.peer_mask;
    if (lease) {
        boards[0] = MBSCAN_DHCP_SERVER_IP;
        nb = 1;
        mask = MBSCAN_DHCP_MASK;
    } else {
        for (i = 0; i < MBS_TABLE_SIZE; ++i)
            if (snap.e[i].used && snap.e[i].role == MBS_ROLE_SELF)
                peers[np++] = snap.e[i].ip;
        nb = mbs_choose_board(e->ip, known_mask, boards, 4);
        mask = nb != 0U ? mbs_choose_mask(boards[0], peers, np, known_mask) : 0U;
    }
    refresh_vlan();
    ethernetif_vlan_id = tx_vlan; /* lwIP traffic follows the peer's VLAN */

    for (bi = 0; bi < nb; ++bi) {
        uint32_t b = boards[bi];
        if (!lease && !board_free(b, e))
            continue;
        if (must_abort())
            return 0;
        apply_board(b, mask);
        vt->board_ip = b;
        vt->board_mask = mask;
        send_arp(1, b, b); /* gratuitous ARP: the peer learns the board */
        if (arp_resolve(e, b))
            d->arp_alive = 1;
        if (d->arp_alive && d->confidence < MBS_CONF_ARP)
            d->confidence = MBS_CONF_ARP;
        r502 = probe_port(d, e->ip, 502U);
        if (r502 == MBSCAN_TCP_OPEN || r502 == MBSCAN_TCP_REFUSED) {
            reached = 1;
            break;
        }
        /* silence: the peer may consider the board off-link; try the next address */
    }
    d->tcp_outcome = r502;
#if MBSCAN_ALT_PORTS
    if ((reached || d->arp_alive) && !d->modbus_valid && !must_abort()) {
        static const uint16_t alt[3] = {5020U, 1502U, 10502U};
        unsigned k;
        for (k = 0; k < 3U && !d->modbus_valid; ++k) {
            uint32_t r = tcp_try(e->ip, alt[k], 600U);
            if (r == MBSCAN_TCP_OPEN) {
                if (d->confidence < MBS_CONF_TCP)
                    d->confidence = MBS_CONF_TCP;
                modbus_session(d, alt[k]);
                tcp_end();
            }
        }
    }
#endif
    if (vt->board_ip != 0U) {
        mbs_ip_str(d->board_ip, vt->board_ip);
        mbs_ip_str(d->board_mask, vt->board_mask);
    }
    vt->conf = d->confidence;
    return 1;
}

static int stage_verify(void)
{
    MbsEntry cands[MBSCAN_MAX_VERIFY];
    MbScanDevice dev;
    VerifyTarget vt;
    unsigned n, i, kept = 0;
    uint32_t best_conf = 0;
    VerifyTarget bestvt;

    set_state(MBSCAN_ST_VERIFY);
    taskENTER_CRITICAL();
    n = mbs_pick_candidates(&ctx, cands, MBSCAN_MAX_VERIFY);
    taskEXIT_CRITICAL();
    memset(&bestvt, 0, sizeof(bestvt));
    for (i = 0; i < n && kept < MBSCAN_MAX_RESULTS; ++i) {
        if (!verify_candidate(&cands[i], &dev, &vt)) {
            if (must_abort())
                return R_RESTART;
            continue;
        }
        pub_device(kept, &dev);
        result_board_ip[kept] = vt.board_ip;
        result_board_mask[kept] = vt.board_mask;
        if (dev.confidence > best_conf) {
            best_conf = dev.confidence;
            bestvt = vt;
        }
        ++kept;
        mbscan_status.found = kept;
    }
    if (kept == 0U)
        return R_NONE;
    /* Leave the board configured in the best device's subnet. */
    if (bestvt.board_ip != 0U) {
        apply_board(bestvt.board_ip, bestvt.board_mask);
    }
    return R_FOUND;
}

/* ------------------------------------------------------------------------ */
/* Stage 6: failure handling                                                 */
/* ------------------------------------------------------------------------ */

static int stage_vendor(void)
{
    uint32_t xid = HAL_GetTick();
    set_state(MBSCAN_ST_VENDOR);
    refresh_vlan();
    /* PROFINET DCP Identify-All works at layer 2 without any IP address */
    (void)tx_frame(mbs_build_dcp_identify_all(txbuf, tx_vlan, gnetif.hwaddr, xid));
    /* EtherNet/IP ListIdentity from a link-local source address */
    (void)tx_frame(mbs_build_enip_listidentity(txbuf, tx_vlan, gnetif.hwaddr,
                                               MBS_IP(169, 254, 77, 77)));
    if (sleep_found(MBSCAN_VENDOR_LISTEN_MS))
        return sleep_chk(MBSCAN_SETTLE_MS) ? R_RESTART : R_FOUND;
    return must_abort() ? R_RESTART : R_NONE;
}

/* The peer only talks about addresses that are not its own (gateway, master).
 * It may sit behind a router, where ARP cannot reach it: try TCP 502 on those
 * hint addresses from a board address next to each one. */
static int stage_routed(void)
{
    uint32_t hints[3];
    unsigned nh, i, kept = mbscan_status.found;
    MbScanDevice dev;

    snapshot();
    nh = mbs_collect_hints(&snap, hints, 3);
    for (i = 0; i < nh && kept < MBSCAN_MAX_RESULTS; ++i) {
        uint32_t boards[2], mask;
        uint32_t r;
        if (snap_find(hints[i], MBS_ROLE_SELF) != NULL)
            continue;
        if (mbs_choose_board(hints[i], 0, boards, 2) == 0U)
            continue;
        mask = mbs_choose_mask(boards[0], &hints[i], 1, 0);
        apply_board(boards[0], mask);
        memset(&dev, 0, sizeof(dev));
        mbs_ip_str(dev.ip, hints[i]);
        dev.methods = MBS_SRC_ROUTED;
        dev.confidence = MBS_CONF_HINT;
        r = probe_port(&dev, hints[i], 502U);
        dev.tcp_outcome = r;
        if (r == MBSCAN_TCP_OPEN) {
            mbs_ip_str(dev.board_ip, boards[0]);
            mbs_ip_str(dev.board_mask, mask);
            pub_device(kept, &dev);
            result_board_ip[kept] = boards[0];
            result_board_mask[kept] = mask;
            ++kept;
            mbscan_status.found = kept;
            return R_FOUND;
        }
        if (must_abort())
            return R_RESTART;
    }
    apply_board(0, 0);
    return R_NONE;
}

static uint32_t classify_failure(void)
{
    uint32_t reason;
    uint32_t hints[2];
    pub_counters();
    taskENTER_CRITICAL();
    snap = ctx;
    taskEXIT_CRITICAL();
    if (!netif_is_link_up(&gnetif))
        reason = MBSCAN_FAIL_NO_LINK;
    else if (snap.wildcard)
        reason = MBSCAN_FAIL_WILDCARD;
    else if (snap.frames == 0U || !snap.peer_mac_valid)
        reason = (mbscan_status.crc_errors + mbscan_status.align_errors) > 4U
                     ? MBSCAN_FAIL_RX_ERRORS
                     : MBSCAN_FAIL_NO_TRAFFIC;
    else if (snap.vlan_seen)
        reason = MBSCAN_FAIL_VLAN;
    else if (mbs_collect_hints(&snap, hints, 2) != 0U)
        reason = MBSCAN_FAIL_HINT_ONLY;
    else
        reason = MBSCAN_FAIL_NOT_FOUND;
    return reason;
}

/* ------------------------------------------------------------------------ */
/* one scan cycle                                                            */
/* ------------------------------------------------------------------------ */

static void tap_start(void)
{
    ctx_reset();
    tap_on = 1;
    ethernetif_rx_tap = rx_tap;
    apply_filter(1);
}

static void tap_stop(void)
{
    tap_on = 0;
    ethernetif_rx_tap = NULL;
    apply_filter(0);
}

static int run_cycle(unsigned cycle)
{
    int r;
    uint32_t t0;

    cycle_no = cycle;
    mbscan_status.found = 0;
    memset(mbscan_result, 0, sizeof(mbscan_result));
    /* Stage 0: no address, no DHCP/AutoIP, promiscuous, tap before lwIP */
    (void)netifapi_netif_common(&gnetif, addressing_stop_cb, NULL);
    apply_board(0, 0);
    ethernetif_vlan_id = 0;
    tx_vlan = 0;
    tap_start();
    ethernetif_read_counters(&crc0, &align0, &missed0);
    if (!wait_link(MBSCAN_LINK_WAIT_MS)) {
        mbscan_status.fail_reason = MBSCAN_FAIL_NO_LINK;
        return R_NONE;
    }
    phy_diag();
    t0 = HAL_GetTick(); /* listening starts now; after a bounce it restarts at the new link-up */

    /* Stage 1: passive. First cycle: short listen (device may already run),
     * then bounce the link so it repeats its start-up sequence. */
    if (cycle == 0U) {
        r = stage_passive(t0, MBSCAN_FIRST_LISTEN_MS, MBSCAN_FIRST_LISTEN_MS);
        if (r == R_NONE && !ctx.peer_mac_valid && MBSCAN_BOUNCE_ON_START) {
            (void)phy_bounce();
            t0 = link_up_since != 0U ? link_up_since : HAL_GetTick();
            r = stage_passive(t0, MBSCAN_T1_MS, MBSCAN_T1_MAX_MS);
        } else if (r == R_NONE) { /* peer alive: continue the normal window */
            r = stage_passive(t0, MBSCAN_T1_MS, MBSCAN_T1_MAX_MS);
        }
    } else {
        (void)phy_bounce();
        t0 = link_up_since != 0U ? link_up_since : HAL_GetTick();
        r = stage_passive(t0, MBSCAN_T1_MS, MBSCAN_T1_MAX_MS);
    }
    if (r == R_RESTART)
        return r;
    if (r == R_DHCP) { /* Stage 2 */
        r = stage_dhcp();
        if (r == R_RESTART)
            return r;
    }
    if (r != R_FOUND) { /* Stage 3 */
        r = stage_sweep(cycle == 0U);
        if (r == R_RESTART)
            return r;
    }
    if (r == R_FOUND) { /* Stage 4/5 */
        r = stage_verify();
        if (r != R_NONE)
            return r;
    }
    /* Stage 6 */
    r = stage_vendor();
    if (r == R_FOUND)
        r = stage_verify();
    if (r == R_NONE)
        r = stage_routed();
    if (r == R_NONE)
        mbscan_status.fail_reason = classify_failure();
    return r;
}

/* ------------------------------------------------------------------------ */
/* task                                                                      */
/* ------------------------------------------------------------------------ */

static void scan_entry(void const *argument)
{
    uint32_t seen_gen;
    (void)argument;

    for (;;) {
        unsigned cycle = 0, restarts = 0;
        int r = R_NONE;

        mbscan_cmd = 0;
        scan_start_ms = HAL_GetTick();
        dhcp_acks = 0;
        mbscan_status.fail_reason = MBSCAN_FAIL_NONE;
        while (cycle < MBSCAN_MAX_CYCLES) {
            r = run_cycle(cycle);
            if (r == R_RESTART && restarts < 20U) {
                ++restarts;
                if (mbscan_cmd != 0U) {
                    mbscan_cmd = 0;
                    cycle = 0;
                    scan_start_ms = HAL_GetTick();
                }
                continue;
            }
            if (r == R_FOUND)
                break;
            ++cycle;
        }
        tap_stop();
        ctx_set_solicit(0);
        pub_counters();
        pub_status();
        if (r == R_FOUND) {
            mbscan_status.fail_reason = MBSCAN_FAIL_NONE;
            set_state(MBSCAN_ST_DONE);
        } else {
            set_state(MBSCAN_ST_FAILED);
            if (mbscan_status.fail_reason == MBSCAN_FAIL_NONE)
                mbscan_status.fail_reason = MBSCAN_FAIL_NOT_FOUND;
            apply_board(0, 0);
#if MBSCAN_FALLBACK_TO_DHCP
            NetworkIdentity_StartAddressing(); /* previous behaviour: DHCP, then AutoIP */
#endif
        }

        /* Idle: wait for a rescan request or (optionally) a cable re-plug. */
        seen_gen = link_up_since;
        for (;;) {
            osDelay(250);
            if (mbscan_cmd != 0U)
                break;
#if MBSCAN_AUTORESCAN_ON_RELINK
            if (link_up_since != seen_gen && link_up_since != 0U)
                break;
#endif
        }
    }
}

osThreadId MbScan_Start(void)
{
    if (scan_task == NULL) {
        osSemaphoreDef(MbTcp);
        mbs_ctx_init(&ctx, gnetif.hwaddr);
        tcp_sem = osSemaphoreCreate(osSemaphore(MbTcp), 1);
        if (tcp_sem == NULL)
            return NULL;
        (void)osSemaphoreWait(tcp_sem, 0);
        osThreadDef(MbScan, scan_entry, osPriorityBelowNormal, 0, MBSCAN_TASK_STACK_WORDS);
        scan_task = osThreadCreate(osThread(MbScan), NULL);
    }
    return scan_task;
}

void MbScan_Rescan(void)
{
    mbscan_cmd = 1;
}

#else /* !MBSCAN_ENABLE */

osThreadId MbScan_Start(void)
{
    return NULL;
}

void MbScan_Rescan(void)
{
}

#endif
