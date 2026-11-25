/* Host unit tests for Core/Src/mbscan_core.c (no hardware, no lwIP). */
#include "mbscan_core.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t OWN[6] = {2, 0, 0, 0, 0, 1};
static const uint8_t DEV[6] = {0x00, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F};
static const uint8_t BC[6] = {255, 255, 255, 255, 255, 255};
static MbsCtx C;

static void be16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void be32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

static void fresh(void) { mbs_ctx_init(&C, OWN); }

static unsigned arp(uint8_t *f, const uint8_t *src, unsigned op, uint32_t spa, uint32_t tpa, unsigned vlan)
{
    unsigned n = mbs_build_arp(f, 0, BC, src, op, NULL, spa, tpa);
    (void)vlan;
    return n;
}

/* IPv4/UDP frame from DEV */
static unsigned udp(uint8_t *f, uint32_t sip, uint32_t dip, unsigned sp, unsigned dp,
                    const uint8_t *pl, unsigned pn, int good_csum)
{
    uint8_t *ip = f + 14;
    memcpy(f, BC, 6); memcpy(f + 6, DEV, 6); be16(f + 12, 0x0800);
    ip[0] = 0x45; ip[1] = 0; be16(ip + 2, 28 + pn); be16(ip + 4, 0); be16(ip + 6, 0);
    ip[8] = 64; ip[9] = 17; be16(ip + 10, 0); be32(ip + 12, sip); be32(ip + 16, dip);
    be16(ip + 10, mbs_ip_checksum(ip, 20));
    if (!good_csum) ip[10] ^= 0x55;
    be16(ip + 20, sp); be16(ip + 22, dp); be16(ip + 24, 8 + pn); be16(ip + 26, 0);
    memcpy(ip + 28, pl, pn);
    return 14 + 28 + pn;
}

static unsigned tcp(uint8_t *f, uint32_t sip, uint32_t dip, unsigned sp, unsigned dp)
{
    uint8_t *ip = f + 14;
    memset(f, 0, 80);
    memcpy(f, OWN, 6); memcpy(f + 6, DEV, 6); be16(f + 12, 0x0800);
    ip[0] = 0x45; be16(ip + 2, 40); ip[8] = 64; ip[9] = 6;
    be32(ip + 12, sip); be32(ip + 16, dip); be16(ip + 10, mbs_ip_checksum(ip, 20));
    be16(ip + 20, sp); be16(ip + 22, dp); ip[32] = 0x50;
    return 54;
}

static const MbsEntry *find(uint32_t ip, unsigned role)
{
    unsigned i;
    for (i = 0; i < MBS_TABLE_SIZE; i++)
        if (C.e[i].used && C.e[i].ip == ip && C.e[i].role == role) return &C.e[i];
    return NULL;
}

static void test_helpers(void)
{
    char s[16], m[18];
    assert(mbs_ip_unicast_valid(MBS_IP(192, 168, 1, 10)));
    assert(!mbs_ip_unicast_valid(0) && !mbs_ip_unicast_valid(0xFFFFFFFFUL));
    assert(!mbs_ip_unicast_valid(MBS_IP(224, 0, 0, 251)) && !mbs_ip_unicast_valid(MBS_IP(127, 0, 0, 1)));
    assert(!mbs_ip_unicast_valid(MBS_IP(240, 0, 0, 1)));
    assert(mbs_ip_link_local(MBS_IP(169, 254, 3, 4)) && !mbs_ip_link_local(MBS_IP(169, 253, 3, 4)));
    mbs_ip_str(s, MBS_IP(10, 0, 255, 7)); assert(!strcmp(s, "10.0.255.7"));
    mbs_ip_str(s, 0); assert(!strcmp(s, "0.0.0.0"));
    mbs_mac_str(m, DEV); assert(!strcmp(m, "00:1B:2C:3D:4E:5F"));
    assert(mbs_prefix_to_mask(24) == 0xFFFFFF00UL && mbs_prefix_to_mask(0) == 0 && mbs_prefix_to_mask(32) == 0xFFFFFFFFUL);
}

static void test_arp(void)
{
    uint8_t f[128]; unsigned n; uint32_t ev; const MbsEntry *e;
    /* ARP probe: sender 0, target = configured IP */
    fresh();
    n = arp(f, DEV, 1, 0, MBS_IP(192, 168, 7, 20), 0);
    assert(n == 60);
    ev = mbs_rx_frame(&C, f, n, 100);
    assert(ev & MBS_EV_NEW_SELF);
    e = find(MBS_IP(192, 168, 7, 20), MBS_ROLE_SELF);
    assert(e && e->conf == MBS_CONF_OBSERVED && (e->sources & MBS_SRC_ARP_PROBE) && e->mac_valid && !memcmp(e->mac, DEV, 6));
    assert(C.arp_probes_seen == 1);
    /* gratuitous / announce */
    n = arp(f, DEV, 1, MBS_IP(192, 168, 7, 20), MBS_IP(192, 168, 7, 20), 0);
    mbs_rx_frame(&C, f, n, 200);
    e = find(MBS_IP(192, 168, 7, 20), MBS_ROLE_SELF);
    assert(e->sources & MBS_SRC_ARP_ANNOUNCE && e->count == 2);
    /* normal request: sender SELF, target HINT (gateway) */
    fresh();
    n = arp(f, DEV, 1, MBS_IP(10, 0, 0, 5), MBS_IP(10, 0, 0, 1), 0);
    mbs_rx_frame(&C, f, n, 5);
    assert(find(MBS_IP(10, 0, 0, 5), MBS_ROLE_SELF));
    e = find(MBS_IP(10, 0, 0, 1), MBS_ROLE_HINT);
    assert(e && e->conf == MBS_CONF_HINT && !e->mac_valid && (e->sources & MBS_SRC_ARP_TARGET));
    assert(mbs_count_self(&C) == 1);
    /* reply while sweeping -> CONF_ARP, otherwise OBSERVED */
    fresh(); C.solicit = 1;
    n = arp(f, DEV, 2, MBS_IP(169, 254, 9, 9), MBS_IP(0, 0, 0, 0), 0);
    mbs_rx_frame(&C, f, n, 5);
    e = find(MBS_IP(169, 254, 9, 9), MBS_ROLE_SELF);
    assert(e && e->conf == MBS_CONF_ARP && (e->sources & MBS_SRC_ARP_REPLY));
    /* own frames, bad frames, invalid sender are not evidence */
    fresh();
    n = arp(f, OWN, 1, MBS_IP(1, 2, 3, 4), MBS_IP(1, 2, 3, 5), 0);
    assert(mbs_rx_frame(&C, f, n, 1) & MBS_EV_IGNORED);
    n = arp(f, DEV, 1, MBS_IP(224, 1, 1, 1), MBS_IP(1, 2, 3, 5), 0);
    mbs_rx_frame(&C, f, n, 1);
    assert(mbs_count_self(&C) == 0);
    n = arp(f, DEV, 1, MBS_IP(1, 2, 3, 4), MBS_IP(1, 2, 3, 5), 0);
    f[14 + 5] = 5; /* plen != 4 */
    assert(mbs_rx_frame(&C, f, n, 1) & MBS_EV_BAD);
    assert(mbs_rx_frame(&C, f, 10, 1) & MBS_EV_BAD);
    f[6] |= 1; /* multicast source */
    assert(mbs_rx_frame(&C, f, n, 1) & MBS_EV_BAD);
    /* wildcard: one MAC answers 4 different IPs */
    fresh(); C.solicit = 1;
    for (n = 0; n < 4; n++) {
        unsigned l = arp(f, DEV, 2, MBS_IP(192, 168, 1, 10 + n), 0, 0);
        ev = mbs_rx_frame(&C, f, l, 10 + n);
    }
    assert(C.wildcard && (ev & MBS_EV_WILDCARD));
}

static void test_vlan_ip(void)
{
    uint8_t f[128], t[128]; unsigned n, i; const MbsEntry *e;
    fresh();
    n = mbs_build_arp(f, 42, BC, DEV, 1, NULL, MBS_IP(10, 9, 9, 9), MBS_IP(10, 9, 9, 1));
    assert(n == 60 && f[12] == 0x81 && f[13] == 0x00);
    assert(mbs_rx_frame(&C, f, n, 1) & MBS_EV_VLAN);
    assert(C.vlan_seen && C.vlan_id == 42 && find(MBS_IP(10, 9, 9, 9), MBS_ROLE_SELF));
    /* priority tag (vid 0) is not a VLAN */
    fresh();
    n = mbs_build_arp(f, 0, BC, DEV, 1, NULL, MBS_IP(10, 9, 9, 9), MBS_IP(10, 9, 9, 1));
    memmove(f + 16, f + 12, n - 12); be16(f + 12, 0x8100); be16(f + 14, 0x6000);
    mbs_rx_frame(&C, f, n + 4, 1);
    assert(!C.vlan_seen && find(MBS_IP(10, 9, 9, 9), MBS_ROLE_SELF));
    /* IPv4 good checksum -> SELF, bad checksum -> HINT only */
    fresh();
    n = udp(f, MBS_IP(172, 16, 4, 4), MBS_IP(172, 16, 4, 255), 1234, 9999, (const uint8_t *)"x", 1, 1);
    mbs_rx_frame(&C, f, n, 1);
    e = find(MBS_IP(172, 16, 4, 4), MBS_ROLE_SELF);
    assert(e && e->conf == MBS_CONF_OBSERVED && (e->sources & MBS_SRC_IPV4));
    fresh();
    n = udp(f, MBS_IP(172, 16, 4, 4), MBS_IP(172, 16, 4, 255), 1234, 9999, (const uint8_t *)"x", 1, 0);
    assert(mbs_rx_frame(&C, f, n, 1) & MBS_EV_BAD);
    assert(mbs_count_self(&C) == 0 && find(MBS_IP(172, 16, 4, 4), MBS_ROLE_HINT));
    /* truncated IP total length */
    n = udp(f, MBS_IP(172, 16, 4, 4), 1, 1, 1, (const uint8_t *)"x", 1, 1);
    fresh();
    assert(mbs_rx_frame(&C, f, n - 5, 1) & MBS_EV_BAD);
    /* TCP port 502: src 502 => SELF flag, dst 502 => HINT */
    fresh();
    n = tcp(t, MBS_IP(192, 168, 3, 3), MBS_IP(192, 168, 3, 1), 40000, 502);
    mbs_rx_frame(&C, t, n, 1);
    assert(find(MBS_IP(192, 168, 3, 1), MBS_ROLE_HINT) && find(MBS_IP(192, 168, 3, 3), MBS_ROLE_SELF));
    n = tcp(t, MBS_IP(192, 168, 3, 3), MBS_IP(192, 168, 3, 1), 502, 40000);
    mbs_rx_frame(&C, t, n, 2);
    assert(find(MBS_IP(192, 168, 3, 3), MBS_ROLE_SELF)->sources & MBS_SRC_MB502);
    /* table overflow: HINTs never push out SELF */
    fresh();
    n = arp(f, DEV, 1, MBS_IP(10, 0, 0, 5), MBS_IP(10, 0, 0, 1), 0);
    mbs_rx_frame(&C, f, n, 1);
    for (i = 0; i < 20; i++) mbs_note(&C, MBS_IP(10, 1, 0, 10 + i), NULL, MBS_ROLE_HINT, MBS_CONF_HINT, 1, 10 + i);
    assert(find(MBS_IP(10, 0, 0, 5), MBS_ROLE_SELF));
}

static unsigned dhcp(uint8_t *f, unsigned type, uint32_t ciaddr, uint32_t req, uint32_t sid, unsigned flags, const char *host)
{
    uint8_t b[300], *o = b + 240; unsigned n;
    memset(b, 0, sizeof b);
    b[0] = 1; b[1] = 1; b[2] = 6; be32(b + 4, 0xCAFEBABEUL); be16(b + 10, flags); be32(b + 12, ciaddr);
    memcpy(b + 28, DEV, 6); b[236] = 0x63; b[237] = 0x82; b[238] = 0x53; b[239] = 0x63;
    *o++ = 53; *o++ = 1; *o++ = type;
    if (req) { *o++ = 50; *o++ = 4; be32(o, req); o += 4; }
    if (sid) { *o++ = 54; *o++ = 4; be32(o, sid); o += 4; }
    if (host) { *o++ = 12; *o++ = (uint8_t)strlen(host); memcpy(o, host, strlen(host)); o += strlen(host); }
    *o++ = 255;
    n = udp(f, ciaddr, ciaddr ? MBS_IP(192, 168, 50, 1) : 0xFFFFFFFFUL, 68, 67, b, 300, 1);
    return n;
}

static void test_dhcp(void)
{
    uint8_t f[512], r[512]; unsigned n, rn; MbsDhcpReq rq; const uint32_t S = MBS_IP(192, 168, 50, 1), O = MBS_IP(192, 168, 50, 100);
    uint32_t seq;
    fresh();
    n = dhcp(f, 1, 0, 0, 0, 0x8000, "plc-7");
    assert(mbs_rx_frame(&C, f, n, 10) & MBS_EV_DHCP);
    assert(C.dhcp_client && C.dhcp_seq == 1 && !strcmp(C.hostname, "plc-7"));
    assert(mbs_count_self(&C) == 0); /* source 0.0.0.0 is no evidence */
    rq = C.dhcp_req;
    assert(rq.valid && rq.msg_type == 1 && rq.xid == 0xCAFEBABEUL && !memcmp(rq.chaddr, DEV, 6));
    assert(mbs_dhcp_decide(&rq, S, O) == MBS_DHCP_OFFER);
    rn = mbs_dhcp_build_reply(r, sizeof r, 0, &rq, MBS_DHCP_OFFER, OWN, S, O, 0xFFFFFF00UL, 86400);
    assert(rn == 14 + 20 + 8 + 300);
    assert(mbs_ip_checksum(r + 14, 20) == 0);
    assert(!memcmp(r, BC, 6) && !memcmp(r + 6, OWN, 6));
    assert(r[14 + 20 + 8] == 2 && r[14 + 28 + 240] == 53 && r[14 + 28 + 242] == 2);
    assert(((uint32_t)r[14 + 28 + 16] << 24 | r[14 + 28 + 17] << 16 | r[14 + 28 + 18] << 8 | r[14 + 28 + 19]) == O);
    assert(r[14 + 28 + 236] == 0x63 && r[14 + 21] == 67 && r[14 + 23] == 68);
    /* REQUEST for our offer (selecting) -> ACK; other server -> ignore; other IP -> NAK */
    n = dhcp(f, 3, 0, O, S, 0x8000, NULL); mbs_rx_frame(&C, f, n, 20);
    assert(C.dhcp_seq == 2);
    assert(mbs_dhcp_decide(&C.dhcp_req, S, O) == MBS_DHCP_ACK);
    n = dhcp(f, 3, 0, O, MBS_IP(1, 1, 1, 1), 0, NULL); mbs_rx_frame(&C, f, n, 21);
    assert(mbs_dhcp_decide(&C.dhcp_req, S, O) == 0);
    n = dhcp(f, 3, 0, MBS_IP(192, 168, 1, 9), 0, 0, NULL); mbs_rx_frame(&C, f, n, 22);
    assert(mbs_dhcp_decide(&C.dhcp_req, S, O) == MBS_DHCP_NAK);
    rq = C.dhcp_req;
    rn = mbs_dhcp_build_reply(r, sizeof r, 0, &rq, MBS_DHCP_NAK, OWN, S, O, 0xFFFFFF00UL, 1);
    assert(rn && r[14 + 28 + 242] == 6);
    assert(find(MBS_IP(192, 168, 1, 9), MBS_ROLE_HINT)); /* option 50 is only a hint */
    /* renewal: unicast to ciaddr and client MAC */
    n = dhcp(f, 3, O, 0, 0, 0, NULL); mbs_rx_frame(&C, f, n, 30);
    seq = C.dhcp_seq; rq = C.dhcp_req;
    assert(mbs_dhcp_decide(&rq, S, O) == MBS_DHCP_ACK);
    rn = mbs_dhcp_build_reply(r, sizeof r, 0, &rq, MBS_DHCP_ACK, OWN, S, O, 0xFFFFFF00UL, 86400);
    assert(!memcmp(r, DEV, 6) && r[14 + 16] == 192 && r[14 + 19] == 100 && seq);
    /* VLAN tagged reply */
    rn = mbs_dhcp_build_reply(r, sizeof r, 7, &rq, MBS_DHCP_ACK, OWN, S, O, 0xFFFFFF00UL, 86400);
    assert(rn == 14 + 20 + 8 + 300 + 4 && r[12] == 0x81 && r[15] == 7);
    assert(mbs_dhcp_build_reply(r, 100, 0, &rq, MBS_DHCP_ACK, OWN, S, O, 0, 1) == 0);
    /* INFORM is not a lease client */
    fresh(); n = dhcp(f, 8, 0, 0, 0, 0, NULL); mbs_rx_frame(&C, f, n, 1);
    assert(!C.dhcp_client);
}

static void test_other_protocols(void)
{
    uint8_t f[512], p[200]; unsigned n, o; const MbsEntry *e;
    /* mDNS answer with A record, compressed name */
    fresh();
    memset(p, 0, sizeof p);
    be16(p + 6, 1);                       /* ancount */
    o = 12; p[o++] = 3; memcpy(p + o, "plc", 3); o += 3; p[o++] = 5; memcpy(p + o, "local", 5); o += 5; p[o++] = 0;
    be16(p + o, 1); be16(p + o + 2, 1); be32(p + o + 4, 120); be16(p + o + 8, 4); be32(p + o + 10, MBS_IP(192, 168, 9, 9)); o += 14;
    n = udp(f, MBS_IP(192, 168, 9, 9), MBS_IP(224, 0, 0, 251), 5353, 5353, p, o, 1);
    mbs_rx_frame(&C, f, n, 1);
    e = find(MBS_IP(192, 168, 9, 9), MBS_ROLE_SELF);
    assert(e && (e->sources & MBS_SRC_MDNS));
    /* NBNS registration advertising another address -> hint */
    fresh();
    memset(p, 0, sizeof p);
    be16(p + 4, 1); be16(p + 10, 1);       /* qd=1 ar=1 */
    o = 12; p[o++] = 0x20; memset(p + o, 'A', 32); o += 32; p[o++] = 0; be16(p + o, 0x20); be16(p + o + 2, 1); o += 4;
    p[o++] = 0xC0; p[o++] = 0x0C; be16(p + o, 0x20); be16(p + o + 2, 1); be32(p + o + 4, 300); be16(p + o + 8, 6);
    be16(p + o + 10, 0); be32(p + o + 12, MBS_IP(192, 168, 9, 77)); o += 16;
    n = udp(f, MBS_IP(192, 168, 9, 9), 0xFFFFFFFFUL, 137, 137, p, o, 1);
    mbs_rx_frame(&C, f, n, 1);
    assert(find(MBS_IP(192, 168, 9, 77), MBS_ROLE_HINT));
    /* SSDP NOTIFY with LOCATION */
    fresh();
    n = udp(f, MBS_IP(192, 168, 2, 2), MBS_IP(239, 255, 255, 250), 1900, 1900,
            (const uint8_t *)"NOTIFY * HTTP/1.1\r\nHost: x\r\nLocation: http://192.168.2.2:80/d.xml\r\n\r\n", 69, 1);
    mbs_rx_frame(&C, f, n, 1);
    e = find(MBS_IP(192, 168, 2, 2), MBS_ROLE_SELF);
    assert(e && (e->sources & MBS_SRC_SSDP));
    /* malformed DNS must not crash */
    fresh(); memset(p, 0xFF, sizeof p);
    n = udp(f, MBS_IP(192, 168, 2, 2), 0xFFFFFFFFUL, 5353, 5353, p, 100, 1); mbs_rx_frame(&C, f, n, 1);
    /* LLDP with management address */
    fresh();
    memcpy(f, "\x01\x80\xC2\x00\x00\x0E", 6); memcpy(f + 6, DEV, 6); be16(f + 12, 0x88CC);
    o = 14;
    be16(f + o, (1 << 9) | 7); f[o + 2] = 4; memcpy(f + o + 3, "\x00\x11\x22\x33\x44\x55", 6); o += 9;       /* chassis MAC */
    be16(f + o, (8 << 9) | 12); f[o + 2] = 5; f[o + 3] = 1; be32(f + o + 4, MBS_IP(10, 20, 30, 40)); f[o + 8] = 2; be32(f + o + 9 - 0, 1); o += 14;
    be16(f + o, 0); o += 2;
    mbs_rx_frame(&C, f, o, 1);
    e = find(MBS_IP(10, 20, 30, 40), MBS_ROLE_SELF);
    assert(e && (e->sources & MBS_SRC_LLDP));
    /* PROFINET DCP Identify response with IP block */
    fresh();
    memcpy(f, OWN, 6); memcpy(f + 6, DEV, 6); be16(f + 12, 0x8892);
    be16(f + 14, 0xFEFF); f[16] = 5; f[17] = 1; be32(f + 18, 1); be16(f + 22, 0);
    be16(f + 24, 18);              /* one IP block: 4 header + 14 data */
    f[26] = 1; f[27] = 2; be16(f + 28, 14); be16(f + 30, 1);
    be32(f + 32, MBS_IP(192, 168, 0, 77)); be32(f + 36, 0xFFFFFF00UL); be32(f + 40, MBS_IP(192, 168, 0, 1));
    mbs_rx_frame(&C, f, 44, 1);
    e = find(MBS_IP(192, 168, 0, 77), MBS_ROLE_SELF);
    assert(e && (e->sources & MBS_SRC_DCP) && C.peer_mask == 0xFFFFFF00UL && C.peer_gw == MBS_IP(192, 168, 0, 1));
    f[17] = 0;                      /* a controller's request must be ignored */
    fresh(); mbs_rx_frame(&C, f, 44, 1);
    assert(mbs_count_self(&C) == 0);
}

static void test_builders(void)
{
    uint8_t f[160]; unsigned n;
    static const uint8_t z[6] = {0};
    n = mbs_build_arp(f, 0, BC, OWN, 1, NULL, 0, MBS_IP(169, 254, 1, 1));
    assert(n == 60 && !memcmp(f, BC, 6) && !memcmp(f + 6, OWN, 6) && f[12] == 8 && f[13] == 6);
    assert(f[14 + 7] == 1 && !memcmp(f + 14 + 8, OWN, 6) && !memcmp(f + 14 + 14, z, 4) && !memcmp(f + 14 + 18, z, 6));
    assert(f[14 + 24] == 169 && f[14 + 25] == 254 && f[14 + 26] == 1 && f[14 + 27] == 1 && f[50] == 0);
    n = mbs_build_dcp_identify_all(f, 0, OWN, 7);
    assert(n == 60 && f[0] == 1 && f[1] == 0x0E && f[12] == 0x88 && f[13] == 0x92 && f[14] == 0xFE && f[15] == 0xFE && f[16] == 5);
    n = mbs_build_enip_listidentity(f, 0, OWN, MBS_IP(169, 254, 10, 10));
    assert(n == 14 + 52 && mbs_ip_checksum(f + 14, 20) == 0 && f[14 + 28] == 0x63 && f[14 + 23] == 0x12 && f[14 + 22] == 0xAF);
    /* build -> parse round trip into evidence */
    fresh();
    n = mbs_build_arp(f, 0, BC, DEV, 1, NULL, 0, MBS_IP(192, 168, 5, 5));
    mbs_rx_frame(&C, f, n, 1);
    assert(find(MBS_IP(192, 168, 5, 5), MBS_ROLE_SELF));
}

static void test_candidates(void)
{
    MbsCand c; uint32_t v[2] = {MBS_IP(192, 168, 1, 100), 0}, h[3] = {MBS_IP(192, 168, 7, 20), MBS_IP(192, 168, 7, 99), MBS_IP(10, 4, 4, 4)};
    uint32_t sum = 0, i;
    mbs_cand_build(&c, 1, NULL, 0, NULL, 0);
    assert(c.total == 65024 && mbs_cand_get(&c, 0) == MBS_IP(169, 254, 1, 0) && mbs_cand_get(&c, 65023) == MBS_IP(169, 254, 254, 255));
    mbs_cand_build(&c, 2, NULL, 0, NULL, 0);
    assert(c.total == 508 && mbs_cand_get(&c, 0) == MBS_IP(192, 168, 0, 1) && mbs_cand_get(&c, 253) == MBS_IP(192, 168, 0, 254));
    assert(mbs_cand_get(&c, 254) == MBS_IP(192, 168, 1, 1) && mbs_cand_get(&c, 507) == MBS_IP(192, 168, 1, 254));
    mbs_cand_build(&c, 3, NULL, 0, NULL, 0);
    assert(c.total == 4 * 254 && mbs_cand_get(&c, 508) == MBS_IP(10, 1, 1, 1) && mbs_cand_get(&c, 762) == MBS_IP(10, 10, 10, 1));
    mbs_cand_build(&c, 4, NULL, 0, NULL, 0);
    assert(c.total == 508 && mbs_cand_get(&c, 254) == MBS_IP(172, 16, 1, 1));
    mbs_cand_build(&c, 5, NULL, 0, NULL, 0);
    assert(c.total == 254UL * 254UL && mbs_cand_get(&c, 0) == MBS_IP(192, 168, 2, 1) && mbs_cand_get(&c, c.total - 1) == MBS_IP(192, 168, 255, 254));
    mbs_cand_build(&c, 6, NULL, 0, NULL, 0);
    assert(mbs_cand_get(&c, c.total - 1) == MBS_IP(172, 31, 255, 254) && mbs_cand_get(&c, 0) == MBS_IP(172, 16, 2, 1));
    mbs_cand_build(&c, 7, NULL, 0, NULL, 0);
    assert(c.n == 3 && c.total == 65532UL * 254UL);
    assert(mbs_cand_get(&c, 255UL * 254UL - 1) == MBS_IP(10, 1, 0, 254));       /* last of first range */
    assert(mbs_cand_get(&c, 255UL * 254UL) == MBS_IP(10, 1, 2, 1));             /* P3 block 10.1.1.x skipped */
    assert(mbs_cand_get(&c, (255UL + 2312UL) * 254UL) == MBS_IP(10, 10, 11, 1));/* 10.10.10.x skipped */
    assert(mbs_cand_get(&c, c.total - 1) == MBS_IP(10, 255, 255, 254) && mbs_cand_get(&c, c.total) == 0);
    /* P0: vendor defaults first, then unique /24 blocks around hints */
    mbs_cand_build(&c, 0, h, 3, v, 2);
    assert(c.n == 3 && c.total == 1 + 254 * 2 && mbs_cand_get(&c, 0) == MBS_IP(192, 168, 1, 100));
    assert(mbs_cand_get(&c, 1) == MBS_IP(192, 168, 7, 1) && mbs_cand_get(&c, 255) == MBS_IP(10, 4, 4, 1));
    /* no candidate ever ends in .0/.255 except the link-local group */
    mbs_cand_build(&c, 2, NULL, 0, NULL, 0);
    for (i = 0; i < c.total; i++) { uint32_t a = mbs_cand_get(&c, i) & 255; sum += (a == 0 || a == 255); }
    assert(sum == 0);
}

static void test_board_choice(void)
{
    uint32_t b[5]; unsigned n, i;
    /* /30 partners: .9 <-> .10 must be chosen first */
    n = mbs_choose_board(MBS_IP(192, 168, 1, 10), 0, b, 5);
    assert(n >= 2 && b[0] == MBS_IP(192, 168, 1, 9) && b[1] == MBS_IP(192, 168, 1, 11));
    n = mbs_choose_board(MBS_IP(192, 168, 1, 9), 0, b, 5);
    assert(b[0] == MBS_IP(192, 168, 1, 10));
    /* last-octet 1: dev^3 = .2 ok; dev .254: .253 */
    n = mbs_choose_board(MBS_IP(192, 168, 1, 1), 0, b, 5); assert(b[0] == MBS_IP(192, 168, 1, 2));
    n = mbs_choose_board(MBS_IP(192, 168, 1, 254), 0, b, 5); assert(b[0] == MBS_IP(192, 168, 1, 253));
    /* dev .3: dev^3 = .0 (network) is rejected */
    n = mbs_choose_board(MBS_IP(192, 168, 1, 3), 0, b, 5);
    for (i = 0; i < n; i++) assert((b[i] & 255) != 0 && (b[i] & 255) != 255 && b[i] != MBS_IP(192, 168, 1, 3));
    assert(b[0] == MBS_IP(192, 168, 1, 2));
    /* known mask /30 from DCP */
    n = mbs_choose_board(MBS_IP(10, 0, 0, 5), mbs_prefix_to_mask(30), b, 5);
    assert(n == 1 && b[0] == MBS_IP(10, 0, 0, 6));
    /* link local stays inside 169.254.1.0 - 169.254.254.255 */
    n = mbs_choose_board(MBS_IP(169, 254, 1, 0), 0, b, 5);
    for (i = 0; i < n; i++) assert(b[i] >= MBS_IP(169, 254, 1, 0) && b[i] != MBS_IP(169, 254, 1, 0));
    assert(mbs_choose_mask(MBS_IP(169, 254, 5, 5), NULL, 0, 0) == 0xFFFF0000UL);
    {
        uint32_t peers[2] = {MBS_IP(192, 168, 1, 10), MBS_IP(192, 168, 1, 20)};
        assert(mbs_choose_mask(MBS_IP(192, 168, 1, 9), peers, 2, 0) == 0xFFFFFF00UL);
        peers[1] = MBS_IP(192, 168, 8, 20);
        assert(mbs_choose_mask(MBS_IP(192, 168, 1, 9), peers, 2, 0) == 0xFFFF0000UL);
        peers[1] = MBS_IP(10, 8, 8, 8);
        assert(mbs_choose_mask(MBS_IP(192, 168, 1, 9), peers, 2, 0) == 0xFF000000UL);
        assert(mbs_choose_mask(MBS_IP(192, 168, 1, 9), peers, 2, 0xFFFFFFFCUL) == 0xFFFFFFFCUL);
    }
}

static void test_modbus(void)
{
    uint8_t a[300], q[12]; MbsMbInfo inf; unsigned i;
    assert(mbs_mb_build_read(q, 0x0102, 1, 3, 0, 1) == 12);
    assert(!memcmp(q, "\x01\x02\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01", 12));
    memcpy(a, "\x01\x02\x00\x00\x00\x05\x01\x03\x02\x12\x34", 11);
    for (i = 0; i < 11; i++) assert(mbs_mb_check_read(a, i, 0x0102, 1, 3, 1, &inf) == MBS_MB_NEED_MORE);
    assert(mbs_mb_check_read(a, 11, 0x0102, 1, 3, 1, &inf) == MBS_MB_OK && inf.frame_len == 11 && !inf.unit_mismatch);
    assert(mbs_mb_check_read(a, 11, 0x0103, 1, 3, 1, &inf) == MBS_MB_INVALID);           /* tid */
    a[3] = 1; assert(mbs_mb_check_read(a, 11, 0x0102, 1, 3, 1, &inf) == MBS_MB_INVALID); a[3] = 0; /* protocol */
    a[5] = 6; assert(mbs_mb_check_read(a, 11, 0x0102, 1, 3, 1, &inf) != MBS_MB_OK); a[5] = 5;      /* length */
    a[8] = 4; assert(mbs_mb_check_read(a, 11, 0x0102, 1, 3, 1, &inf) == MBS_MB_INVALID); a[8] = 2; /* byte count */
    a[6] = 7; assert(mbs_mb_check_read(a, 11, 0x0102, 1, 3, 1, &inf) == MBS_MB_OK && inf.unit_mismatch); a[6] = 1;
    a[7] = 4; assert(mbs_mb_check_read(a, 11, 0x0102, 1, 3, 1, &inf) == MBS_MB_INVALID); a[7] = 3;
    /* exception */
    memcpy(a, "\x00\x09\x00\x00\x00\x03\x01\x83\x02", 9);
    assert(mbs_mb_check_read(a, 9, 9, 1, 3, 1, &inf) == MBS_MB_EXCEPTION && inf.exception == 2);
    a[8] = 0; assert(mbs_mb_check_read(a, 9, 9, 1, 3, 1, &inf) == MBS_MB_INVALID);
    a[8] = 0x0B; assert(mbs_mb_check_read(a, 9, 9, 1, 3, 1, &inf) == MBS_MB_EXCEPTION);
    a[5] = 4; assert(mbs_mb_check_read(a, 9, 9, 1, 3, 1, &inf) != MBS_MB_EXCEPTION);
    /* HTTP garbage is not Modbus */
    assert(mbs_mb_check_read((const uint8_t *)"HTTP/1.1 400 Bad Request", 24, 1, 1, 3, 1, &inf) == MBS_MB_INVALID);
    /* device identification */
    assert(mbs_mb_build_devid(q, 5, 1, 1, 0) == 11 && !memcmp(q, "\x00\x05\x00\x00\x00\x05\x01\x2B\x0E\x01\x00", 11));
    {
        const uint8_t r[] = {0, 5, 0, 0, 0, 0, 1, 0x2B, 0x0E, 1, 0x81, 0, 0, 3,
                             0, 4, 'A', 'c', 'm', 'e', 1, 3, 'X', '-', '1', 2, 3, 'v', '1', '2'};
        uint8_t m[40]; char v[16], p[16], rv[16];
        memcpy(m, r, sizeof r); be16(m + 4, sizeof r - 6);
        assert(mbs_mb_check_devid(m, sizeof r, 5, 1, &inf) == MBS_MB_OK);
        mbs_mb_parse_devid(m, sizeof r, v, sizeof v, p, sizeof p, rv, sizeof rv);
        assert(!strcmp(v, "Acme") && !strcmp(p, "X-1") && !strcmp(rv, "v12"));
        be16(m + 4, sizeof r - 6 - 1);
        assert(mbs_mb_check_devid(m, sizeof r - 1, 5, 1, &inf) == MBS_MB_INVALID);
        mbs_mb_parse_devid(m, sizeof r, v, 3, p, 2, rv, 1);  /* tiny buffers stay terminated */
        assert(strlen(v) == 2 && strlen(p) == 1 && !rv[0]);
        memcpy(m, "\x00\x05\x00\x00\x00\x03\x01\xAB\x01", 9);
        assert(mbs_mb_check_devid(m, 9, 5, 1, &inf) == MBS_MB_EXCEPTION);
    }
}

static void test_ctx(void)
{
    MbsEntry out[4]; uint32_t ips[6]; unsigned n;
    fresh();
    mbs_note(&C, MBS_IP(10, 0, 0, 2), DEV, MBS_ROLE_SELF, MBS_CONF_OBSERVED, MBS_SRC_IPV4, 5);
    mbs_note(&C, MBS_IP(10, 0, 0, 3), DEV, MBS_ROLE_SELF, MBS_CONF_ARP, MBS_SRC_ARP_REPLY, 4);
    mbs_note(&C, MBS_IP(10, 0, 0, 4), NULL, MBS_ROLE_HINT, MBS_CONF_HINT, MBS_SRC_ARP_TARGET, 6);
    C.dhcp_req_ip = MBS_IP(10, 0, 0, 3);
    C.peer_gw = MBS_IP(10, 0, 0, 1);
    n = mbs_pick_candidates(&C, out, 4);
    assert(n == 2 && out[0].ip == MBS_IP(10, 0, 0, 3) && out[1].ip == MBS_IP(10, 0, 0, 2)); /* conf first */
    assert(mbs_collect_hints(&C, ips, 6) == 4);                                            /* deduplicated */
    C.own_ip = MBS_IP(10, 0, 0, 2);
    {
        uint32_t v = C.version, s = C.dhcp_seq;
        mbs_ctx_reset_evidence(&C);
        assert(C.version > v && C.dhcp_seq == s && mbs_count_self(&C) == 0 && C.own_ip == MBS_IP(10, 0, 0, 2));
        assert(!memcmp(C.own_mac, OWN, 6));
    }
}

int main(void)
{
    test_helpers();
    test_arp();
    test_vlan_ip();
    test_dhcp();
    test_other_protocols();
    test_builders();
    test_candidates();
    test_board_choice();
    test_modbus();
    test_ctx();
    puts("PASS: mbscan core - parser (ARP/IPv4/VLAN/DHCP/mDNS/NBNS/SSDP/LLDP/DCP), builders, DHCP rescue policy, candidate groups, board address choice, Modbus validators");
    return 0;
}
