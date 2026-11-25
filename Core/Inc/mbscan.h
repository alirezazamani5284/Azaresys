#ifndef MBSCAN_H
#define MBSCAN_H

/* Hybrid Modbus-TCP device IP discovery - firmware integration.
 * One task owns the Ethernet interface while it scans:
 *   Stage 0 prepare   : no IP address, promiscuous MAC, raw frame tap before lwIP
 *   Stage 1 passive   : listen from link-up (ARP/probe/DHCP/IPv4/LLDP/DCP/mDNS/NBNS/SSDP)
 *   Stage 2 DHCP      : minimal DHCP server when the peer asks for an address
 *   Stage 3 ARP sweep : prioritised candidate groups P0..P7, pass A (sender 0.0.0.0)
 *                       then pass B (neighbour sender), rate limited, evidence driven
 *   Stage 4 verify    : choose an on-link board address, resolve, TCP 502, Modbus checks
 *   Stage 5 output    : mbscan_result[] / mbscan_status (debugger Watch)
 *   Stage 6 failure   : PHY link bounce, PROFINET DCP / EtherNet-IP probes, routed hints
 * The passive listener runs in every stage: new evidence preempts active stages.
 * Details: docs/MODBUS_SCAN_FA.md
 */

#include <stdint.h>
#include "cmsis_os.h"
#include "mbscan_config.h"
#include "mbscan_core.h"

/* mbscan_status.state */
#define MBSCAN_ST_OFF       0U
#define MBSCAN_ST_WAIT_LINK 1U
#define MBSCAN_ST_PASSIVE   2U
#define MBSCAN_ST_DHCP      3U
#define MBSCAN_ST_SWEEP     4U
#define MBSCAN_ST_VERIFY    5U
#define MBSCAN_ST_VENDOR    6U
#define MBSCAN_ST_DONE      7U /* at least one device reported */
#define MBSCAN_ST_FAILED    8U /* all cycles used, nothing found */

/* mbscan_status.fail_reason */
#define MBSCAN_FAIL_NONE      0U
#define MBSCAN_FAIL_NO_LINK   1U /* no cable / PHY link */
#define MBSCAN_FAIL_NO_TRAFFIC 2U /* link up, not one valid frame received */
#define MBSCAN_FAIL_RX_ERRORS 3U /* CRC/alignment errors: speed/duplex mismatch or bad cable */
#define MBSCAN_FAIL_VLAN      4U /* VLAN tagged frames seen, nothing usable */
#define MBSCAN_FAIL_HINT_ONLY 5U /* only referenced addresses (gateway/master): routed segment? */
#define MBSCAN_FAIL_WILDCARD  6U /* a MAC answered every ARP probe (proxy ARP) */
#define MBSCAN_FAIL_NOT_FOUND 7U /* peer alive but no usable address */

/* MbScanDevice.tcp_outcome */
#define MBSCAN_TCP_NONE     0U
#define MBSCAN_TCP_OPEN     1U /* connection accepted */
#define MBSCAN_TCP_REFUSED  2U /* RST: host reachable, port closed */
#define MBSCAN_TCP_TIMEOUT  3U /* no answer */
#define MBSCAN_TCP_ERROR    4U /* no route / no memory */

typedef struct {
    char ip[16];
    char mac[18];
    char board_ip[16];            /* address the board used to reach the device */
    char board_mask[16];
    char vendor[24];              /* Modbus device identification (FC 0x2B/0x0E) */
    char product[24];
    char revision[16];
    uint32_t port;                /* Modbus TCP port that answered, 0 = none */
    uint32_t port502_open;        /* connection to port 502 accepted */
    uint32_t modbus_valid;        /* strictly validated Modbus TCP reply */
    uint32_t gateway;             /* exception 0x0A/0x0B seen: TCP->RTU gateway */
    uint32_t unit_ids[4];         /* units that answered */
    uint32_t unit_count;
    uint32_t arp_alive;           /* the device answered ARP from the board's address */
    uint32_t tcp_outcome;         /* MBSCAN_TCP_* for port 502 */
    uint32_t confidence;          /* MBS_CONF_* */
    uint32_t methods;             /* MBS_SRC_* bit mask: discovery_method */
} MbScanDevice;

typedef struct {
    uint32_t state;
    uint32_t cycle;
    uint32_t found;               /* number of reported devices */
    uint32_t fail_reason;
    uint32_t elapsed_ms;          /* since the scan started */
    uint32_t group;               /* sweep progress: group P0..P7 */
    uint32_t group_total;
    uint32_t group_done;
    uint32_t pass_b;              /* 1 while pass B is running */
    uint32_t rate_pps;
    uint32_t probes_sent;
    uint32_t tx_drops;            /* raw frames that could not be queued */
    uint32_t frames_rx;           /* frames seen by the tap */
    uint32_t frames_bad;
    uint32_t arp_probes_seen;
    uint32_t dhcp_client;         /* DEVICE_IS_DHCP_CLIENT */
    uint32_t dhcp_acks;
    uint32_t wildcard;
    uint32_t vlan_id;
    uint32_t crc_errors;          /* MAC counters since the cycle start */
    uint32_t align_errors;
    uint32_t missed_frames;
    uint32_t link_mismatch;       /* 0 ok, 1 ANEG result differs from MAC, 2 partner without ANEG but MAC full duplex */
    uint32_t link_age_ms;
    char peer_mac[18];
    char hostname[16];
} MbScanStatus;

extern MbScanStatus mbscan_status;
extern MbScanDevice mbscan_result[MBSCAN_MAX_RESULTS];
/* Debugger controls: write 1 to mbscan_cmd to start a new scan; set
 * mbscan_allow_p7 to 1 to allow the hours-long 10.0.0.0/8 sweep (P7). */
extern volatile uint32_t mbscan_cmd;
extern volatile uint32_t mbscan_allow_p7;

/* Create the scanner task once after lwIP init; NULL if disabled or on failure. */
osThreadId MbScan_Start(void);
/* Ask for a new scan (same as mbscan_cmd = 1). */
void MbScan_Rescan(void);

#endif
