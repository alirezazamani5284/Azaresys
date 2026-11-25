#ifndef MBSCAN_CONFIG_H
#define MBSCAN_CONFIG_H

/* ------------------------------------------------------------------------
 * Hybrid Modbus-TCP device IP discovery - compile-time configuration.
 * Every value is a default; override with -D or by editing this file.
 * Times are milliseconds, rates are frames per second.
 * ---------------------------------------------------------------------- */

/* 1 = the scanner owns the Ethernet interface after boot (DHCP/AutoIP is held
 * back until the scan has finished or failed). 0 = firmware behaves exactly as
 * before: DHCP + AutoIP from boot, scanner task is not created. */
#ifndef MBSCAN_ENABLE
#define MBSCAN_ENABLE 1
#endif

/* After a failed scan (all cycles) restore the previous behaviour: DHCP, then
 * AutoIP. After a successful scan the board keeps its static address. */
#ifndef MBSCAN_FALLBACK_TO_DHCP
#define MBSCAN_FALLBACK_TO_DHCP 1
#endif

/* Restart the scan automatically when the cable is unplugged and re-plugged
 * after a scan has already finished (device swapped). */
#ifndef MBSCAN_AUTORESCAN_ON_RELINK
#define MBSCAN_AUTORESCAN_ON_RELINK 1
#endif

/* ---- Stage 1: passive discovery ---------------------------------------- */
#ifndef MBSCAN_T1_MS
#define MBSCAN_T1_MS 10000U            /* base listening window, from link-up */
#endif
#ifndef MBSCAN_T1_MAX_MS
#define MBSCAN_T1_MAX_MS 60000U        /* extension limit while the peer is alive */
#endif
#ifndef MBSCAN_T1_EXTEND_MS
#define MBSCAN_T1_EXTEND_MS 10000U
#endif
#ifndef MBSCAN_SETTLE_MS
#define MBSCAN_SETTLE_MS 300U          /* extra listening after the first valid candidate */
#endif
#ifndef MBSCAN_BOUNCE_ON_START
#define MBSCAN_BOUNCE_ON_START 1       /* bounce the PHY link when the first listen heard nothing */
#endif
#ifndef MBSCAN_FIRST_LISTEN_MS
#define MBSCAN_FIRST_LISTEN_MS 2000U   /* short listen (device already running?) before the bounce */
#endif
#ifndef MBSCAN_LINK_WAIT_MS
#define MBSCAN_LINK_WAIT_MS 60000U     /* how long one cycle waits for the cable */
#endif
#ifndef MBSCAN_BOUNCE_DOWN_MS
#define MBSCAN_BOUNCE_DOWN_MS 800U     /* PHY power-down time during a bounce */
#endif

/* ---- Stage 2: DHCP rescue ----------------------------------------------- */
#ifndef MBSCAN_DHCP_SERVER_IP
#define MBSCAN_DHCP_SERVER_IP    0xC0A83201UL  /* 192.168.50.1   */
#endif
#ifndef MBSCAN_DHCP_OFFER_IP
#define MBSCAN_DHCP_OFFER_IP     0xC0A83264UL  /* 192.168.50.100 */
#endif
#ifndef MBSCAN_DHCP_MASK
#define MBSCAN_DHCP_MASK         0xFFFFFF00UL  /* 255.255.255.0  */
#endif
#ifndef MBSCAN_DHCP_LEASE_S
#define MBSCAN_DHCP_LEASE_S      86400UL
#endif
#ifndef MBSCAN_DHCP_WINDOW_MS
#define MBSCAN_DHCP_WINDOW_MS    30000U
#endif

/* ---- Stage 3: active ARP sweep ------------------------------------------ */
#ifndef MBSCAN_RATE_PPS
#define MBSCAN_RATE_PPS 400U           /* 200..1000 */
#endif
#ifndef MBSCAN_RATE_MIN_PPS
#define MBSCAN_RATE_MIN_PPS 100U       /* adaptive floor after TX drops */
#endif
#ifndef MBSCAN_GROUP_WAIT_MS
#define MBSCAN_GROUP_WAIT_MS 500U      /* wait for late replies after each group/round */
#endif
#ifndef MBSCAN_DRAIN_MS
#define MBSCAN_DRAIN_MS 300U           /* extra listening after the first sweep hit */
#endif
#ifndef MBSCAN_SMALL_GROUP
#define MBSCAN_SMALL_GROUP 4096U       /* groups up to this size are swept twice (ARP has no retransmit) */
#endif
/* P5 (rest of 192.168/16, ~3 min) and P6 (172.16/12, ~45 min at 400 pps) are part of
 * the first cycle; later cycles only repeat the small groups. */
#ifndef MBSCAN_SWEEP_P5_P6
#define MBSCAN_SWEEP_P5_P6 1
#endif
/* P7 (rest of 10.0.0.0/8, many hours) runs only if this is 1 or the debugger
 * variable mbscan_allow_p7 is set to 1 by the user. */
#ifndef MBSCAN_ALLOW_P7
#define MBSCAN_ALLOW_P7 0
#endif

/* Optional vendor default IPs (P0, highest priority). Up to 4 host-order
 * constants, EACH FOLLOWED BY A COMMA, e.g.  0xC0A8010AUL, 0xC0A80164UL,
 * Leave empty when unknown. */
#ifndef MBSCAN_VENDOR_DEFAULTS
#define MBSCAN_VENDOR_DEFAULTS
#endif

/* ---- Stage 4: verification ----------------------------------------------- */
#ifndef MBSCAN_ARP_PROBE_WAIT_MS
#define MBSCAN_ARP_PROBE_WAIT_MS 300U  /* free-address check for the board IP */
#endif
#ifndef MBSCAN_ARP_RESOLVE_MS
#define MBSCAN_ARP_RESOLVE_MS 300U
#endif
#ifndef MBSCAN_TCP_TIMEOUT_MS
#define MBSCAN_TCP_TIMEOUT_MS 1500U    /* one SYN attempt */
#endif
#ifndef MBSCAN_TCP_ATTEMPTS
#define MBSCAN_TCP_ATTEMPTS 2U
#endif
#ifndef MBSCAN_MB_TIMEOUT_MS
#define MBSCAN_MB_TIMEOUT_MS 1500U     /* first Modbus request per unit */
#endif
#ifndef MBSCAN_MB_SCAN_TIMEOUT_MS
#define MBSCAN_MB_SCAN_TIMEOUT_MS 250U /* unit-ID scan 2..247 */
#endif
#ifndef MBSCAN_UNIT_SCAN_BUDGET_MS
#define MBSCAN_UNIT_SCAN_BUDGET_MS 15000U
#endif
#ifndef MBSCAN_ALT_PORTS
#define MBSCAN_ALT_PORTS 1             /* also try 5020, 1502, 10502 when 502 is not Modbus */
#endif
#ifndef MBSCAN_MAX_VERIFY
#define MBSCAN_MAX_VERIFY 3U           /* candidates verified per cycle */
#endif

/* ---- Stage 6: failure handling ------------------------------------------- */
#ifndef MBSCAN_MAX_CYCLES
#define MBSCAN_MAX_CYCLES 3U
#endif
#ifndef MBSCAN_VENDOR_LISTEN_MS
#define MBSCAN_VENDOR_LISTEN_MS 3000U
#endif

/* ---- Task / memory ------------------------------------------------------- */
#ifndef MBSCAN_TASK_STACK_WORDS
#define MBSCAN_TASK_STACK_WORDS 512U
#endif
#ifndef MBSCAN_MAX_RESULTS
#define MBSCAN_MAX_RESULTS 2U
#endif

#endif
