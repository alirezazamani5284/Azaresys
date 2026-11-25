#ifndef MBSCAN_CORE_H
#define MBSCAN_CORE_H

/* Hardware-independent logic of the hybrid Modbus-TCP IP discovery:
 * raw frame parser + evidence table, frame builders, DHCP mini server policy,
 * candidate address generator, board address choice and Modbus validators.
 * No lwIP, HAL or RTOS dependency: the file is unit-tested on a PC.
 * All IPv4 addresses are host-order uint32_t (192.168.1.10 = 0xC0A8010A).
 * Thread rule: mbs_rx_frame() has a single writer (the Ethernet RX task);
 * readers copy the context inside a critical section (see mbscan.c).
 */

#include <stdint.h>
#include <stddef.h>

#define MBS_IP(a, b, c, d) ((((uint32_t)(a)) << 24) | (((uint32_t)(b)) << 16) | \
                            (((uint32_t)(c)) << 8) | ((uint32_t)(d)))

/* ---- evidence sources (bit flags kept per table entry) ------------------- */
#define MBS_SRC_ARP_SENDER   0x0001U /* sender IP of an ARP request/reply/gratuitous */
#define MBS_SRC_ARP_PROBE    0x0002U /* RFC 5227 probe: target = the configured IP */
#define MBS_SRC_ARP_ANNOUNCE 0x0004U /* sender IP == target IP */
#define MBS_SRC_IPV4         0x0008U /* source address of an IPv4 packet */
#define MBS_SRC_DHCP_REQIP   0x0010U /* DHCP option 50 (hint) */
#define MBS_SRC_MB502        0x0020U /* TCP/UDP port 502 endpoint */
#define MBS_SRC_LLDP         0x0040U
#define MBS_SRC_DCP          0x0080U /* PROFINET DCP IP block */
#define MBS_SRC_MDNS         0x0100U
#define MBS_SRC_NBNS         0x0200U
#define MBS_SRC_SSDP         0x0400U
#define MBS_SRC_DHCP_LEASE   0x0800U /* address handed out by our own DHCP rescue */
#define MBS_SRC_ARP_REPLY    0x1000U /* ARP reply (answer to a sweep probe) */
#define MBS_SRC_ENIP         0x2000U /* EtherNet/IP port 44818/2222 */
#define MBS_SRC_ARP_TARGET   0x4000U /* target IP of a normal ARP request (hint) */
#define MBS_SRC_ROUTED       0x8000U /* found by TCP probing of a hint address */

/* role: whose address is it? */
#define MBS_ROLE_SELF 1U /* the sender's own address (ARP sender/probe, IP source ...) */
#define MBS_ROLE_HINT 2U /* an address the peer merely talked about (gateway, master ...) */

/* confidence levels */
#define MBS_CONF_NONE     0U
#define MBS_CONF_HINT     1U
#define MBS_CONF_OBSERVED 2U /* seen passively as the peer's own address */
#define MBS_CONF_ARP      3U /* answered an ARP probe / assigned by our DHCP / ARP-resolved */
#define MBS_CONF_TCP      4U /* TCP connection accepted on a Modbus port */
#define MBS_CONF_MODBUS   5U /* valid Modbus TCP reply */

#define MBS_TABLE_SIZE 8U

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
    uint8_t role;
    uint8_t conf;
    uint8_t mac_valid;
    uint8_t used;
    uint16_t sources;
    uint16_t count;
    uint32_t first_ms;
    uint32_t last_ms;
} MbsEntry;

/* A DHCP request seen on the wire, for the rescue server. */
typedef struct {
    uint8_t msg_type;      /* 1 DISCOVER, 3 REQUEST, ... */
    uint8_t has_req_ip;
    uint8_t has_server_id;
    uint8_t valid;
    uint16_t flags;
    uint32_t xid;
    uint32_t ciaddr;
    uint32_t req_ip;
    uint32_t server_id;
    uint8_t chaddr[6];
    uint8_t src_mac[6];
} MbsDhcpReq;

typedef struct {
    uint8_t own_mac[6];
    uint32_t own_ip;               /* ignored as evidence; 0 = none */
    uint8_t solicit;               /* 1 while sweeping: ARP replies count as CONF_ARP */
    MbsEntry e[MBS_TABLE_SIZE];

    /* global facts about the peer */
    uint8_t dhcp_client;           /* DEVICE_IS_DHCP_CLIENT */
    uint32_t dhcp_req_ip;          /* option 50 */
    char hostname[16];             /* option 12 (printable ASCII, truncated) */
    uint8_t vlan_seen;
    uint16_t vlan_id;
    uint8_t peer_mac[6];
    uint8_t peer_mac_valid;
    uint32_t last_frame_ms;
    uint32_t peer_mask;            /* reported by PROFINET DCP, 0 = unknown */
    uint32_t peer_gw;

    /* counters */
    uint32_t frames, frames_arp, frames_ip, frames_other, frames_bad, frames_ignored;
    uint32_t arp_probes_seen;

    /* "answers every address" detection (proxy ARP / odd stacks) */
    uint8_t wildcard;
    uint8_t rep_mac[6];
    uint32_t rep_ip[4];
    uint8_t rep_n;

    MbsDhcpReq dhcp_req;           /* last DISCOVER/REQUEST */
    uint32_t dhcp_seq;             /* incremented for every stored request */
    uint32_t version;              /* incremented on every meaningful change */
} MbsCtx;

/* events returned by mbs_rx_frame (bit mask) */
#define MBS_EV_NEW_SELF 0x01U
#define MBS_EV_DHCP     0x02U
#define MBS_EV_VLAN     0x04U
#define MBS_EV_BAD      0x08U
#define MBS_EV_IGNORED  0x10U
#define MBS_EV_WILDCARD 0x20U

/* ---- helpers --------------------------------------------------------------- */
int mbs_ip_unicast_valid(uint32_t ip);     /* not 0, not bcast/multicast/class E/loopback */
int mbs_ip_link_local(uint32_t ip);        /* 169.254.0.0/16 */
uint16_t mbs_ip_checksum(const uint8_t *data, size_t len); /* ones-complement sum, folded */
void mbs_ip_str(char out[16], uint32_t ip);
void mbs_mac_str(char out[18], const uint8_t mac[6]);
uint32_t mbs_prefix_to_mask(unsigned prefix);

/* ---- evidence context --------------------------------------------------------- */
void mbs_ctx_init(MbsCtx *c, const uint8_t own_mac[6]);
void mbs_ctx_reset_evidence(MbsCtx *c);    /* clears table + facts, keeps own_mac/own_ip */
uint32_t mbs_rx_frame(MbsCtx *c, const uint8_t *f, uint16_t len, uint32_t now_ms);
void mbs_note(MbsCtx *c, uint32_t ip, const uint8_t *mac, uint8_t role,
              uint8_t conf, uint16_t source, uint32_t now_ms);
/* SELF entries, best first (confidence, then recency), unique IPs. */
unsigned mbs_pick_candidates(const MbsCtx *c, MbsEntry *out, unsigned max);
unsigned mbs_count_self(const MbsCtx *c);
/* Distinct IPs mentioned by the peer in any role (incl. DHCP option 50, DCP gw). */
unsigned mbs_collect_hints(const MbsCtx *c, uint32_t *ips, unsigned max);

/* ---- frame builders (return frame length without FCS; vlan 0 = untagged) ----- */
uint16_t mbs_build_arp(uint8_t *out, uint16_t vlan, const uint8_t eth_dst[6],
                       const uint8_t own_mac[6], uint16_t op, const uint8_t *tha,
                       uint32_t spa, uint32_t tpa);
uint16_t mbs_build_dcp_identify_all(uint8_t *out, uint16_t vlan,
                                    const uint8_t own_mac[6], uint32_t xid);
uint16_t mbs_build_enip_listidentity(uint8_t *out, uint16_t vlan,
                                     const uint8_t own_mac[6], uint32_t src_ip);

/* ---- DHCP rescue server policy ------------------------------------------------- */
#define MBS_DHCP_OFFER 2
#define MBS_DHCP_ACK   5
#define MBS_DHCP_NAK   6
int mbs_dhcp_decide(const MbsDhcpReq *rq, uint32_t server_ip, uint32_t offer_ip);
uint16_t mbs_dhcp_build_reply(uint8_t *out, uint16_t cap, uint16_t vlan,
                              const MbsDhcpReq *rq, int type, const uint8_t srv_mac[6],
                              uint32_t server_ip, uint32_t offer_ip, uint32_t mask,
                              uint32_t lease_s);

/* ---- candidate generator (random access, no list kept in RAM) -------------------- */
#define MBS_GROUPS 8U            /* P0..P7 */
#define MBS_MAX_RANGES 8U
typedef struct {
    uint32_t first;              /* first IP (BLOCK24: base of the first /24) */
    uint32_t count;              /* number of probe addresses in the range */
    uint8_t block24;             /* 1: /24 blocks, hosts .1-.254 only */
} MbsRange;
typedef struct {
    MbsRange r[MBS_MAX_RANGES];
    uint8_t n;
    uint8_t group;
    uint32_t total;
} MbsCand;
/* group 0 = P0 (vendor defaults + /24 blocks around hints), 1..7 = P1..P7 */
void mbs_cand_build(MbsCand *it, unsigned group, const uint32_t *hint_ips,
                    unsigned nh, const uint32_t *vendor, unsigned nv);
uint32_t mbs_cand_get(const MbsCand *it, uint32_t idx);

/* ---- board address choice --------------------------------------------------------- */
/* Fill 'out' with board IP candidates that are on-link for the device under as
 * many netmasks as possible (flip the lowest bits first). known_mask 0 = unknown. */
unsigned mbs_choose_board(uint32_t dev_ip, uint32_t known_mask, uint32_t *out, unsigned max);
uint32_t mbs_choose_mask(uint32_t board_ip, const uint32_t *peer_ips, unsigned n,
                         uint32_t known_mask);

/* ---- Modbus TCP helpers ----------------------------------------------------------- */
#define MBS_MB_NEED_MORE 0
#define MBS_MB_INVALID   1
#define MBS_MB_OK        2
#define MBS_MB_EXCEPTION 3
typedef struct {
    uint8_t unit;
    uint8_t fc;
    uint8_t exception;       /* valid for MBS_MB_EXCEPTION */
    uint8_t unit_mismatch;   /* reply unit differs from request unit */
    uint16_t frame_len;      /* complete ADU length */
} MbsMbInfo;
uint16_t mbs_mb_build_read(uint8_t adu[12], uint16_t tid, uint8_t unit, uint8_t fc,
                           uint16_t addr, uint16_t qty);
uint16_t mbs_mb_build_devid(uint8_t adu[11], uint16_t tid, uint8_t unit,
                            uint8_t read_code, uint8_t object_id);
/* Strict validation of a FC03/FC04 reply (qty registers requested). */
int mbs_mb_check_read(const uint8_t *buf, uint16_t len, uint16_t tid, uint8_t unit,
                      uint8_t fc, uint16_t qty, MbsMbInfo *info);
/* Validation of a FC 0x2B / MEI 0x0E reply. */
int mbs_mb_check_devid(const uint8_t *buf, uint16_t len, uint16_t tid, uint8_t unit,
                       MbsMbInfo *info);
/* Extract objects 0 (vendor), 1 (product code), 2 (revision) from a valid reply. */
void mbs_mb_parse_devid(const uint8_t *buf, uint16_t len, char *vendor, size_t vcap,
                        char *product, size_t pcap, char *revision, size_t rcap);

#endif
