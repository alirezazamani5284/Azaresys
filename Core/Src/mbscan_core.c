/*
 * Hybrid Modbus-TCP device IP discovery - hardware independent core.
 * See mbscan_core.h. Everything here is plain C99 working on byte buffers.
 */

#include "mbscan_core.h"
#include <string.h>

#define ET_IPV4  0x0800U
#define ET_ARP   0x0806U
#define ET_VLAN  0x8100U
#define ET_QINQ  0x88A8U
#define ET_LLDP  0x88CCU
#define ET_DCP   0x8892U

#define MBS_WILDCARD_LIMIT 4U /* distinct IPs answered by one MAC => answers everything */

/* ------------------------------------------------------------------------ */
/* small helpers                                                             */
/* ------------------------------------------------------------------------ */

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static int mac_zero(const uint8_t *m)
{
    return (m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) == 0U;
}

int mbs_ip_unicast_valid(uint32_t ip)
{
    uint32_t a = ip >> 24;
    if (ip == 0U || ip == 0xFFFFFFFFUL)
        return 0;
    if (a == 0U || a == 127U)
        return 0;
    return a < 224U; /* multicast and class E are never a host address */
}

int mbs_ip_link_local(uint32_t ip)
{
    return (ip >> 16) == 0xA9FEUL;
}

uint16_t mbs_ip_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1U < len; i += 2U)
        sum += rd16(data + i);
    if (len & 1U)
        sum += (uint32_t)data[len - 1U] << 8;
    while (sum >> 16)
        sum = (sum & 0xFFFFU) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFU);
}

static char *put_dec(char *p, unsigned v)
{
    char tmp[3];
    unsigned n = 0;
    do {
        tmp[n++] = (char)('0' + (v % 10U));
        v /= 10U;
    } while (v != 0U);
    while (n != 0U)
        *p++ = tmp[--n];
    return p;
}

void mbs_ip_str(char out[16], uint32_t ip)
{
    char *p = out;
    unsigned i;
    for (i = 0; i < 4U; ++i) {
        p = put_dec(p, (unsigned)((ip >> (24U - 8U * i)) & 0xFFU));
        if (i < 3U)
            *p++ = '.';
    }
    *p = '\0';
}

void mbs_mac_str(char out[18], const uint8_t mac[6])
{
    static const char hex[] = "0123456789ABCDEF";
    unsigned i;
    for (i = 0; i < 6U; ++i) {
        out[3U * i] = hex[mac[i] >> 4];
        out[3U * i + 1U] = hex[mac[i] & 15U];
        if (i < 5U)
            out[3U * i + 2U] = ':';
    }
    out[17] = '\0';
}

uint32_t mbs_prefix_to_mask(unsigned prefix)
{
    if (prefix == 0U)
        return 0U;
    if (prefix >= 32U)
        return 0xFFFFFFFFUL;
    return ~((1UL << (32U - prefix)) - 1UL);
}

static int mask_valid(uint32_t m)
{
    uint32_t inv = ~m;
    return m != 0U && inv >= 3U && (inv & (inv + 1U)) == 0U; /* /1../30 contiguous */
}

/* ------------------------------------------------------------------------ */
/* evidence table                                                            */
/* ------------------------------------------------------------------------ */

void mbs_ctx_init(MbsCtx *c, const uint8_t own_mac[6])
{
    memset(c, 0, sizeof(*c));
    memcpy(c->own_mac, own_mac, 6);
}

void mbs_ctx_reset_evidence(MbsCtx *c)
{
    uint8_t mac[6];
    uint32_t ip = c->own_ip, version = c->version, seq = c->dhcp_seq;
    memcpy(mac, c->own_mac, 6);
    memset(c, 0, sizeof(*c));
    memcpy(c->own_mac, mac, 6);
    c->own_ip = ip;
    c->version = version + 1U;
    c->dhcp_seq = seq;
}

static MbsEntry *find_entry(MbsCtx *c, uint32_t ip, uint8_t role)
{
    unsigned i;
    for (i = 0; i < MBS_TABLE_SIZE; ++i)
        if (c->e[i].used && c->e[i].ip == ip && c->e[i].role == role)
            return &c->e[i];
    return NULL;
}

/* Returns 1 when the table changed in a way a reader should notice. */
static int note_i(MbsCtx *c, uint32_t ip, const uint8_t *mac, uint8_t role,
                  uint8_t conf, uint16_t source, uint32_t now)
{
    MbsEntry *e = find_entry(c, ip, role);
    int changed = 0;
    unsigned i;

    if (e == NULL) {
        MbsEntry *victim = NULL;
        for (i = 0; i < MBS_TABLE_SIZE; ++i)
            if (!c->e[i].used) {
                victim = &c->e[i];
                break;
            }
        if (victim == NULL) {
            /* Replace the oldest HINT first; a SELF entry only evicts a weaker SELF. */
            for (i = 0; i < MBS_TABLE_SIZE; ++i)
                if (c->e[i].role == MBS_ROLE_HINT &&
                    (victim == NULL || c->e[i].last_ms < victim->last_ms))
                    victim = &c->e[i];
            if (victim == NULL && role == MBS_ROLE_SELF)
                for (i = 0; i < MBS_TABLE_SIZE; ++i)
                    if (c->e[i].conf < conf &&
                        (victim == NULL || c->e[i].conf < victim->conf ||
                         (c->e[i].conf == victim->conf && c->e[i].last_ms < victim->last_ms)))
                        victim = &c->e[i];
        }
        if (victim == NULL)
            return 0;
        memset(victim, 0, sizeof(*victim));
        victim->used = 1;
        victim->ip = ip;
        victim->role = role;
        victim->first_ms = now;
        e = victim;
        changed = 1;
    }
    e->last_ms = now;
    if (e->count < 0xFFFFU)
        ++e->count;
    if ((e->sources & source) != source) {
        e->sources = (uint16_t)(e->sources | source);
        changed = 1;
    }
    if (conf > e->conf) {
        e->conf = conf;
        changed = 1;
    }
    if (mac != NULL && !mac_zero(mac) &&
        (!e->mac_valid || memcmp(e->mac, mac, 6) != 0)) {
        memcpy(e->mac, mac, 6);
        e->mac_valid = 1;
        changed = 1;
    }
    if (changed)
        ++c->version;
    return changed;
}

void mbs_note(MbsCtx *c, uint32_t ip, const uint8_t *mac, uint8_t role,
              uint8_t conf, uint16_t source, uint32_t now_ms)
{
    (void)note_i(c, ip, mac, role, conf, source, now_ms);
}

unsigned mbs_count_self(const MbsCtx *c)
{
    unsigned i, n = 0;
    for (i = 0; i < MBS_TABLE_SIZE; ++i)
        if (c->e[i].used && c->e[i].role == MBS_ROLE_SELF)
            ++n;
    return n;
}

unsigned mbs_pick_candidates(const MbsCtx *c, MbsEntry *out, unsigned max)
{
    unsigned i, j, n = 0;
    for (i = 0; i < MBS_TABLE_SIZE && n < max; ++i) {
        if (!c->e[i].used || c->e[i].role != MBS_ROLE_SELF)
            continue;
        /* insertion sort: higher confidence first, then more recent */
        j = n++;
        while (j > 0U && (out[j - 1U].conf < c->e[i].conf ||
                          (out[j - 1U].conf == c->e[i].conf &&
                           out[j - 1U].last_ms < c->e[i].last_ms))) {
            out[j] = out[j - 1U];
            --j;
        }
        out[j] = c->e[i];
    }
    return n;
}

static unsigned add_unique(uint32_t *ips, unsigned n, unsigned max, uint32_t ip)
{
    unsigned i;
    if (!mbs_ip_unicast_valid(ip))
        return n;
    for (i = 0; i < n; ++i)
        if (ips[i] == ip)
            return n;
    if (n < max)
        ips[n++] = ip;
    return n;
}

unsigned mbs_collect_hints(const MbsCtx *c, uint32_t *ips, unsigned max)
{
    unsigned i, n = 0;
    for (i = 0; i < MBS_TABLE_SIZE; ++i)
        if (c->e[i].used)
            n = add_unique(ips, n, max, c->e[i].ip);
    n = add_unique(ips, n, max, c->dhcp_req_ip);
    n = add_unique(ips, n, max, c->peer_gw);
    return n;
}

/* ------------------------------------------------------------------------ */
/* raw frame parser                                                          */
/* ------------------------------------------------------------------------ */

static uint32_t self_note(MbsCtx *c, uint32_t ip, const uint8_t *mac, uint8_t conf,
                          uint16_t source, uint32_t now)
{
    if (!mbs_ip_unicast_valid(ip) || ip == c->own_ip)
        return 0;
    return note_i(c, ip, mac, MBS_ROLE_SELF, conf, source, now) ? MBS_EV_NEW_SELF : 0U;
}

static void hint_note(MbsCtx *c, uint32_t ip, uint16_t source, uint32_t now)
{
    if (mbs_ip_unicast_valid(ip) && ip != c->own_ip)
        (void)note_i(c, ip, NULL, MBS_ROLE_HINT, MBS_CONF_HINT, source, now);
}

static uint32_t wildcard_check(MbsCtx *c, const uint8_t *mac, uint32_t ip)
{
    unsigned i;
    if (c->rep_n == 0U || memcmp(c->rep_mac, mac, 6) != 0) {
        memcpy(c->rep_mac, mac, 6);
        c->rep_n = 0;
    }
    for (i = 0; i < c->rep_n; ++i)
        if (c->rep_ip[i] == ip)
            return 0;
    if (c->rep_n < MBS_WILDCARD_LIMIT)
        c->rep_ip[c->rep_n++] = ip;
    if (c->rep_n >= MBS_WILDCARD_LIMIT && !c->wildcard) {
        c->wildcard = 1;
        ++c->version;
        return MBS_EV_WILDCARD;
    }
    return 0;
}

static uint32_t parse_arp(MbsCtx *c, const uint8_t *a, uint16_t n, uint32_t now)
{
    uint32_t ev = 0, spa, tpa;
    uint16_t op, src;
    const uint8_t *sha;

    ++c->frames_arp;
    if (n < 28U || rd16(a) != 1U || rd16(a + 2) != ET_IPV4 || a[4] != 6U || a[5] != 4U) {
        ++c->frames_bad;
        return MBS_EV_BAD;
    }
    op = rd16(a + 6);
    if (op != 1U && op != 2U) {
        ++c->frames_bad;
        return MBS_EV_BAD;
    }
    sha = a + 8;
    spa = rd32(a + 14);
    tpa = rd32(a + 24);
    if (mac_zero(sha) || (sha[0] & 1U) || memcmp(sha, c->own_mac, 6) == 0) {
        ++c->frames_ignored;
        return MBS_EV_IGNORED;
    }

    if (spa == 0U) {
        /* RFC 5227 ARP Probe: the target is the address the sender is about to use. */
        if (op == 1U && mbs_ip_unicast_valid(tpa) && tpa != c->own_ip) {
            ++c->arp_probes_seen;
            ev |= self_note(c, tpa, sha, MBS_CONF_OBSERVED, MBS_SRC_ARP_PROBE, now);
        }
        return ev;
    }
    if (!mbs_ip_unicast_valid(spa) || spa == c->own_ip) {
        ++c->frames_ignored;
        return MBS_EV_IGNORED;
    }
    src = MBS_SRC_ARP_SENDER;
    if (tpa == spa)
        src = (uint16_t)(src | MBS_SRC_ARP_ANNOUNCE);
    if (op == 2U)
        src = (uint16_t)(src | MBS_SRC_ARP_REPLY);
    ev |= self_note(c, spa, sha, (op == 2U && c->solicit) ? MBS_CONF_ARP : MBS_CONF_OBSERVED,
                    src, now);
    if (op == 2U)
        ev |= wildcard_check(c, sha, spa);
    else if (tpa != spa)
        hint_note(c, tpa, MBS_SRC_ARP_TARGET, now); /* gateway / master the peer looks for */
    return ev;
}

/* --- DNS style name/record walking (mDNS A records, NBNS NB records) ---- */

static int dns_skip_name(const uint8_t *p, uint16_t len, uint16_t off)
{
    unsigned guard = 0;
    while (guard++ < 64U) {
        uint8_t b;
        if (off >= len)
            return -1;
        b = p[off];
        if (b == 0U)
            return (int)off + 1;
        if ((b & 0xC0U) == 0xC0U)
            return (off + 2U <= len) ? (int)off + 2 : -1;
        if ((b & 0xC0U) != 0U)
            return -1;
        off = (uint16_t)(off + 1U + b);
    }
    return -1;
}

static unsigned dns_find_addr(const uint8_t *p, uint16_t len, int want_nb,
                              uint32_t *ips, unsigned max)
{
    unsigned qd, total, i, found = 0;
    int off = 12;
    if (len < 12U)
        return 0;
    qd = rd16(p + 4);
    total = (unsigned)rd16(p + 6) + rd16(p + 8) + rd16(p + 10);
    if (qd > 16U)
        qd = 16U;
    if (total > 32U)
        total = 32U;
    for (i = 0; i < qd; ++i) {
        off = dns_skip_name(p, len, (uint16_t)off);
        if (off < 0 || off + 4 > (int)len)
            return found;
        off += 4;
    }
    for (i = 0; i < total; ++i) {
        unsigned type, rdlen;
        off = dns_skip_name(p, len, (uint16_t)off);
        if (off < 0 || off + 10 > (int)len)
            break;
        type = rd16(p + off);
        rdlen = rd16(p + off + 8);
        if (off + 10 + (int)rdlen > (int)len)
            break;
        if (!want_nb && type == 1U && rdlen == 4U && found < max)
            ips[found++] = rd32(p + off + 10);
        else if (want_nb && type == 0x20U && rdlen >= 6U && found < max)
            ips[found++] = rd32(p + off + 12);
        off += 10 + (int)rdlen;
    }
    return found;
}

static uint32_t advertised(MbsCtx *c, const uint8_t *eth_src, uint32_t src,
                           const uint32_t *ips, unsigned n, uint16_t source, uint32_t now)
{
    uint32_t ev = 0;
    unsigned i;
    for (i = 0; i < n; ++i) {
        if (ips[i] == src)
            ev |= self_note(c, src, eth_src, MBS_CONF_OBSERVED, source, now);
        else
            hint_note(c, ips[i], source, now);
    }
    return ev;
}

static int ssdp_location(const uint8_t *p, uint16_t len, uint32_t *ip)
{
    static const char key[] = "location:";
    uint16_t i, j;
    for (i = 0; i + 9U < len; ++i) {
        for (j = 0; j < 9U; ++j) {
            uint8_t ch = p[i + j];
            if (ch >= 'A' && ch <= 'Z')
                ch = (uint8_t)(ch + 32U);
            if (ch != (uint8_t)key[j])
                break;
        }
        if (j == 9U) {
            uint16_t k = (uint16_t)(i + 9U);
            uint32_t a = 0, part = 0;
            unsigned digits = 0, dots = 0;
            while (k < len && (p[k] == ' ' || p[k] == '\t'))
                ++k;
            if (k + 7U < len && memcmp(p + k, "http://", 7) == 0)
                k = (uint16_t)(k + 7U);
            else if (k + 8U < len && memcmp(p + k, "https://", 8) == 0)
                k = (uint16_t)(k + 8U);
            for (; k < len; ++k) {
                if (p[k] >= '0' && p[k] <= '9') {
                    part = part * 10U + (uint32_t)(p[k] - '0');
                    if (++digits > 3U || part > 255U)
                        return 0;
                } else if (p[k] == '.' && digits != 0U && dots < 3U) {
                    a = (a << 8) | part;
                    part = 0;
                    digits = 0;
                    ++dots;
                } else {
                    break;
                }
            }
            if (dots == 3U && digits != 0U) {
                *ip = (a << 8) | part;
                return 1;
            }
            return 0;
        }
    }
    return 0;
}

static uint32_t parse_dhcp_request(MbsCtx *c, const uint8_t *eth_src, const uint8_t *b,
                                   uint16_t n, uint32_t now)
{
    MbsDhcpReq rq;
    uint16_t i = 240;
    uint32_t ev = 0;

    if (n < 241U || b[0] != 1U || b[1] != 1U || b[2] != 6U)
        return 0;
    if (b[236] != 0x63U || b[237] != 0x82U || b[238] != 0x53U || b[239] != 0x63U)
        return 0;
    memset(&rq, 0, sizeof(rq));
    rq.xid = rd32(b + 4);
    rq.flags = rd16(b + 10);
    rq.ciaddr = rd32(b + 12);
    memcpy(rq.chaddr, b + 28, 6);
    memcpy(rq.src_mac, eth_src, 6);
    while (i < n) {
        uint8_t code = b[i], olen;
        const uint8_t *o;
        if (code == 255U)
            break;
        if (code == 0U) {
            ++i;
            continue;
        }
        if ((uint16_t)(i + 1U) >= n)
            break;
        olen = b[i + 1U];
        if ((uint32_t)i + 2U + olen > n)
            break;
        o = b + i + 2U;
        if (code == 53U && olen == 1U) {
            rq.msg_type = o[0];
        } else if (code == 50U && olen == 4U) {
            rq.has_req_ip = 1;
            rq.req_ip = rd32(o);
        } else if (code == 54U && olen == 4U) {
            rq.has_server_id = 1;
            rq.server_id = rd32(o);
        } else if (code == 12U && olen != 0U) {
            unsigned k, m = 0;
            for (k = 0; k < olen && m < sizeof(c->hostname) - 1U; ++k)
                if (o[k] >= 0x20U && o[k] < 0x7FU)
                    c->hostname[m++] = (char)o[k];
            c->hostname[m] = '\0';
        }
        i = (uint16_t)(i + 2U + olen);
    }
    if (rq.msg_type == 0U)
        return 0;
    rq.valid = 1;
    if (rq.msg_type == 1U || rq.msg_type == 3U) { /* DISCOVER / REQUEST */
        if (!c->dhcp_client) {
            c->dhcp_client = 1;
            ++c->version;
        }
        c->dhcp_req = rq;
        ++c->dhcp_seq;
        ++c->version;
        ev |= MBS_EV_DHCP;
    }
    if (rq.has_req_ip && mbs_ip_unicast_valid(rq.req_ip)) {
        c->dhcp_req_ip = rq.req_ip;
        hint_note(c, rq.req_ip, MBS_SRC_DHCP_REQIP, now);
    }
    return ev;
}

static uint32_t parse_ipv4(MbsCtx *c, const uint8_t *eth_src, const uint8_t *ip,
                           uint16_t n, uint32_t now)
{
    uint32_t ev = 0, src, dst;
    uint16_t ihl, tot, l4len;
    uint8_t proto;
    int csum_ok;
    const uint8_t *l4;
    uint16_t sport = 0, dport = 0, srcflags = 0;

    ++c->frames_ip;
    if (n < 20U || (ip[0] >> 4) != 4U) {
        ++c->frames_bad;
        return MBS_EV_BAD;
    }
    ihl = (uint16_t)((ip[0] & 15U) * 4U);
    tot = rd16(ip + 2);
    if (ihl < 20U || n < ihl || tot < ihl || tot > n) {
        ++c->frames_bad;
        return MBS_EV_BAD;
    }
    csum_ok = mbs_ip_checksum(ip, ihl) == 0U;
    proto = ip[9];
    src = rd32(ip + 12);
    dst = rd32(ip + 16);
    l4 = ip + ihl;
    l4len = (uint16_t)(tot - ihl);

    /* A source address with a broken header checksum is only a hint. */
    if (csum_ok) {
        ev |= self_note(c, src, eth_src, MBS_CONF_OBSERVED, MBS_SRC_IPV4, now);
    } else {
        ++c->frames_bad;
        hint_note(c, src, MBS_SRC_IPV4, now);
        return ev | MBS_EV_BAD;
    }
    if ((rd16(ip + 6) & 0x1FFFU) != 0U)
        return ev; /* not the first fragment: no L4 header */

    if (proto == 17U && l4len >= 8U) {
        uint16_t ulen = rd16(l4 + 4);
        const uint8_t *pl = l4 + 8;
        uint16_t plen;
        uint32_t ips[4];
        unsigned k;
        sport = rd16(l4);
        dport = rd16(l4 + 2);
        if (ulen < 8U || ulen > l4len)
            return ev;
        plen = (uint16_t)(ulen - 8U);
        if (sport == 68U && dport == 67U)
            ev |= parse_dhcp_request(c, eth_src, pl, plen, now);
        if (sport == 5353U || dport == 5353U) {
            k = dns_find_addr(pl, plen, 0, ips, 4);
            ev |= advertised(c, eth_src, src, ips, k, MBS_SRC_MDNS, now);
        }
        if (sport == 137U || dport == 137U) {
            k = dns_find_addr(pl, plen, 1, ips, 4);
            ev |= advertised(c, eth_src, src, ips, k, MBS_SRC_NBNS, now);
        }
        if (sport == 1900U || dport == 1900U) {
            if (ssdp_location(pl, plen, &ips[0]))
                ev |= advertised(c, eth_src, src, ips, 1, MBS_SRC_SSDP, now);
        }
    } else if (proto == 6U && l4len >= 20U) {
        sport = rd16(l4);
        dport = rd16(l4 + 2);
    } else {
        return ev;
    }

    if (sport == 502U)
        srcflags = MBS_SRC_MB502;
    if (sport == 44818U || sport == 2222U)
        srcflags = (uint16_t)(srcflags | MBS_SRC_ENIP);
    if (srcflags != 0U)
        ev |= self_note(c, src, eth_src, MBS_CONF_OBSERVED, srcflags, now);
    if (dport == 502U)
        hint_note(c, dst, MBS_SRC_MB502, now); /* the peer talks to a Modbus server */
    return ev;
}

static uint32_t parse_lldp(MbsCtx *c, const uint8_t *eth_src, const uint8_t *d,
                           uint16_t n, uint32_t now)
{
    uint32_t ev = 0;
    uint16_t off = 0;
    while ((uint32_t)off + 2U <= n) {
        uint16_t hdr = rd16(d + off), l = (uint16_t)(hdr & 0x1FFU);
        unsigned type = hdr >> 9;
        const uint8_t *v;
        off = (uint16_t)(off + 2U);
        if (type == 0U || (uint32_t)off + l > n)
            break;
        v = d + off;
        if ((type == 1U || type == 8U) && l >= 6U && v[0] == 5U &&
            v[1] == 1U)
            ev |= self_note(c, rd32(v + 2), eth_src, MBS_CONF_OBSERVED, MBS_SRC_LLDP, now);
        off = (uint16_t)(off + l);
    }
    return ev;
}

static uint32_t parse_dcp(MbsCtx *c, const uint8_t *eth_src, const uint8_t *d,
                          uint16_t n, uint32_t now)
{
    uint32_t ev = 0;
    uint16_t fid, dlen, off, end;
    if (n < 12U)
        return 0;
    fid = rd16(d);
    /* Hello (device announces itself) or a response; never a controller's request. */
    if (!(fid == 0xFEFCU || ((fid == 0xFEFDU || fid == 0xFEFFU) && (d[3] & 1U))))
        return 0;
    dlen = rd16(d + 10);
    if (dlen > (uint16_t)(n - 12U))
        dlen = (uint16_t)(n - 12U);
    off = 12;
    end = (uint16_t)(12U + dlen);
    while ((uint32_t)off + 4U <= end) {
        uint16_t blen = rd16(d + off + 2);
        if ((uint32_t)off + 4U + blen > end)
            break;
        if (d[off] == 1U && d[off + 1] == 2U && blen >= 14U) { /* IP / IP parameter */
            uint32_t ip = rd32(d + off + 6), mask = rd32(d + off + 10), gw = rd32(d + off + 14);
            if (mbs_ip_unicast_valid(ip)) {
                ev |= self_note(c, ip, eth_src, MBS_CONF_OBSERVED, MBS_SRC_DCP, now);
                if (mask_valid(mask) && c->peer_mask != mask) {
                    c->peer_mask = mask;
                    ++c->version;
                }
                if (mbs_ip_unicast_valid(gw) && c->peer_gw != gw) {
                    c->peer_gw = gw;
                    ++c->version;
                }
            }
        }
        off = (uint16_t)(off + 4U + blen + (blen & 1U));
    }
    return ev;
}

uint32_t mbs_rx_frame(MbsCtx *c, const uint8_t *f, uint16_t len, uint32_t now_ms)
{
    uint32_t ev = 0;
    uint16_t p, type;
    unsigned tags = 0;
    const uint8_t *src;
    const uint8_t *pl;
    uint16_t pl_len;

    ++c->frames;
    if (len < 14U) {
        ++c->frames_bad;
        return MBS_EV_BAD;
    }
    src = f + 6;
    if ((src[0] & 1U) || mac_zero(src)) {
        ++c->frames_bad;
        return MBS_EV_BAD;
    }
    if (memcmp(src, c->own_mac, 6) == 0) {
        ++c->frames_ignored;
        return MBS_EV_IGNORED;
    }
    memcpy(c->peer_mac, src, 6);
    c->peer_mac_valid = 1;
    c->last_frame_ms = now_ms;

    p = 12;
    type = rd16(f + p);
    while ((type == ET_VLAN || type == ET_QINQ) && tags < 2U) {
        uint16_t vid;
        if ((uint32_t)len < (uint32_t)p + 6U) {
            ++c->frames_bad;
            return ev | MBS_EV_BAD;
        }
        vid = (uint16_t)(rd16(f + p + 2) & 0x0FFFU);
        if (vid != 0U && (!c->vlan_seen || c->vlan_id != vid)) {
            c->vlan_seen = 1;
            c->vlan_id = vid;
            ++c->version;
            ev |= MBS_EV_VLAN;
        }
        p = (uint16_t)(p + 4U);
        type = rd16(f + p);
        ++tags;
    }
    pl = f + p + 2U;
    pl_len = (uint16_t)(len - (p + 2U));

    switch (type) {
    case ET_ARP:
        ev |= parse_arp(c, pl, pl_len, now_ms);
        break;
    case ET_IPV4:
        ev |= parse_ipv4(c, src, pl, pl_len, now_ms);
        break;
    case ET_LLDP:
        ++c->frames_other;
        ev |= parse_lldp(c, src, pl, pl_len, now_ms);
        break;
    case ET_DCP:
        ++c->frames_other;
        ev |= parse_dcp(c, src, pl, pl_len, now_ms);
        break;
    default:
        ++c->frames_other;
        break;
    }
    return ev;
}

/* ------------------------------------------------------------------------ */
/* frame builders                                                            */
/* ------------------------------------------------------------------------ */

#define BUILD_CAP 128U

static void put_eth(uint8_t *out, const uint8_t dst[6], const uint8_t src[6], uint16_t type)
{
    memcpy(out, dst, 6);
    memcpy(out + 6, src, 6);
    wr16(out + 12, type);
}

/* Insert an 802.1Q tag when requested and pad to the 60 byte Ethernet minimum. */
static uint16_t finish_frame(uint8_t *out, uint16_t cap, uint16_t len, uint16_t vlan)
{
    if (vlan != 0U) {
        if ((uint32_t)len + 4U > cap)
            return 0;
        memmove(out + 16, out + 12, (size_t)len - 12U);
        wr16(out + 12, ET_VLAN);
        wr16(out + 14, (uint16_t)(vlan & 0x0FFFU));
        len = (uint16_t)(len + 4U);
    }
    if (len < 60U) {
        if (cap < 60U)
            return 0;
        memset(out + len, 0, 60U - len);
        len = 60;
    }
    return len;
}

uint16_t mbs_build_arp(uint8_t *out, uint16_t vlan, const uint8_t eth_dst[6],
                       const uint8_t own_mac[6], uint16_t op, const uint8_t *tha,
                       uint32_t spa, uint32_t tpa)
{
    static const uint8_t zero[6] = {0, 0, 0, 0, 0, 0};
    uint8_t *a = out + 14;
    put_eth(out, eth_dst, own_mac, ET_ARP);
    wr16(a, 1);
    wr16(a + 2, ET_IPV4);
    a[4] = 6;
    a[5] = 4;
    wr16(a + 6, op);
    memcpy(a + 8, own_mac, 6);
    wr32(a + 14, spa);
    memcpy(a + 18, tha != NULL ? tha : zero, 6);
    wr32(a + 24, tpa);
    return finish_frame(out, BUILD_CAP, 42, vlan);
}

uint16_t mbs_build_dcp_identify_all(uint8_t *out, uint16_t vlan,
                                    const uint8_t own_mac[6], uint32_t xid)
{
    static const uint8_t dst[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};
    uint8_t *d = out + 14;
    put_eth(out, dst, own_mac, ET_DCP);
    wr16(d, 0xFEFEU);   /* Identify request */
    d[2] = 5;           /* ServiceID: Identify */
    d[3] = 0;           /* ServiceType: request */
    wr32(d + 4, xid);
    wr16(d + 8, 1);     /* response delay factor */
    wr16(d + 10, 4);    /* DCPDataLength */
    d[12] = 0xFF;       /* option ALL */
    d[13] = 0xFF;       /* suboption ALL */
    wr16(d + 14, 0);    /* block length */
    return finish_frame(out, BUILD_CAP, 14 + 16, vlan);
}

/* Writes an IPv4+UDP packet after the Ethernet header at out+14. UDP checksum 0
 * (legal for IPv4). Returns the Ethernet frame length without FCS. */
static uint16_t put_udp(uint8_t *out, uint32_t src_ip, uint32_t dst_ip, uint16_t sport,
                        uint16_t dport, uint16_t plen)
{
    uint8_t *ip = out + 14;
    uint16_t total = (uint16_t)(20U + 8U + plen);
    ip[0] = 0x45;
    ip[1] = 0;
    wr16(ip + 2, total);
    wr16(ip + 4, 0);
    wr16(ip + 6, 0);
    ip[8] = 64;
    ip[9] = 17;
    wr16(ip + 10, 0);
    wr32(ip + 12, src_ip);
    wr32(ip + 16, dst_ip);
    wr16(ip + 10, mbs_ip_checksum(ip, 20));
    wr16(ip + 20, sport);
    wr16(ip + 22, dport);
    wr16(ip + 24, (uint16_t)(8U + plen));
    wr16(ip + 26, 0);
    return (uint16_t)(14U + total);
}

uint16_t mbs_build_enip_listidentity(uint8_t *out, uint16_t vlan,
                                     const uint8_t own_mac[6], uint32_t src_ip)
{
    static const uint8_t bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t *pl = out + 14 + 28;
    uint16_t len;
    put_eth(out, bc, own_mac, ET_IPV4);
    memset(pl, 0, 24);
    pl[0] = 0x63; /* ListIdentity, little endian */
    pl[1] = 0x00;
    len = put_udp(out, src_ip, 0xFFFFFFFFUL, 44818U, 44818U, 24);
    return finish_frame(out, BUILD_CAP, len, vlan);
}

/* ------------------------------------------------------------------------ */
/* DHCP rescue server                                                        */
/* ------------------------------------------------------------------------ */

int mbs_dhcp_decide(const MbsDhcpReq *rq, uint32_t server_ip, uint32_t offer_ip)
{
    if (rq == NULL || !rq->valid)
        return 0;
    if (rq->msg_type == 1U)
        return MBS_DHCP_OFFER;
    if (rq->msg_type == 3U) {
        if (rq->has_server_id && rq->server_id != server_ip)
            return 0; /* the client selected another server */
        if (rq->ciaddr != 0U) /* RENEWING / REBINDING */
            return rq->ciaddr == offer_ip ? MBS_DHCP_ACK : MBS_DHCP_NAK;
        if (rq->has_req_ip) /* SELECTING / INIT-REBOOT */
            return rq->req_ip == offer_ip ? MBS_DHCP_ACK : MBS_DHCP_NAK;
    }
    return 0;
}

static uint8_t *opt_u32(uint8_t *o, uint8_t code, uint32_t v)
{
    *o++ = code;
    *o++ = 4;
    wr32(o, v);
    return o + 4;
}

uint16_t mbs_dhcp_build_reply(uint8_t *out, uint16_t cap, uint16_t vlan,
                              const MbsDhcpReq *rq, int type, const uint8_t srv_mac[6],
                              uint32_t server_ip, uint32_t offer_ip, uint32_t mask,
                              uint32_t lease_s)
{
    static const uint8_t bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t *b = out + 14 + 28; /* BOOTP */
    uint8_t *o;
    uint16_t blen, flen;
    uint32_t dst_ip = 0xFFFFFFFFUL;
    const uint8_t *dst_mac = bc;

    if (cap < 14U + 28U + 300U + 4U || rq == NULL ||
        (type != MBS_DHCP_OFFER && type != MBS_DHCP_ACK && type != MBS_DHCP_NAK))
        return 0;
    /* RFC 2131 4.1: renewing clients (ciaddr set, no broadcast flag) get a unicast. */
    if (type != MBS_DHCP_NAK && rq->ciaddr != 0U && !(rq->flags & 0x8000U)) {
        dst_ip = rq->ciaddr;
        dst_mac = rq->chaddr;
    }
    memset(b, 0, 300);
    b[0] = 2; /* BOOTREPLY */
    b[1] = 1;
    b[2] = 6;
    wr32(b + 4, rq->xid);
    wr16(b + 10, rq->flags);
    if (type == MBS_DHCP_ACK)
        wr32(b + 12, rq->ciaddr);
    if (type != MBS_DHCP_NAK) {
        wr32(b + 16, offer_ip);
        wr32(b + 20, server_ip);
    }
    memcpy(b + 28, rq->chaddr, 6);
    b[236] = 0x63;
    b[237] = 0x82;
    b[238] = 0x53;
    b[239] = 0x63;
    o = b + 240;
    *o++ = 53;
    *o++ = 1;
    *o++ = (uint8_t)type;
    o = opt_u32(o, 54, server_ip);
    if (type != MBS_DHCP_NAK) {
        o = opt_u32(o, 51, lease_s);
        o = opt_u32(o, 58, lease_s / 2U);
        o = opt_u32(o, 59, lease_s - lease_s / 8U);
        o = opt_u32(o, 1, mask);
        o = opt_u32(o, 3, server_ip);
    }
    *o++ = 255;
    blen = 300; /* BOOTP minimum for old clients; remaining bytes are zero padding */
    put_eth(out, dst_mac, srv_mac, ET_IPV4);
    flen = put_udp(out, server_ip, dst_ip, 67U, 68U, blen);
    return finish_frame(out, cap, flen, vlan);
}

/* ------------------------------------------------------------------------ */
/* candidate generator                                                       */
/* ------------------------------------------------------------------------ */

static void add_range(MbsCand *it, uint32_t first, uint32_t count, uint8_t block24)
{
    if (count != 0U && it->n < MBS_MAX_RANGES) {
        it->r[it->n].first = first;
        it->r[it->n].count = count;
        it->r[it->n].block24 = block24;
        ++it->n;
        it->total += count;
    }
}

void mbs_cand_build(MbsCand *it, unsigned group, const uint32_t *hint_ips,
                    unsigned nh, const uint32_t *vendor, unsigned nv)
{
    unsigned i, j;
    memset(it, 0, sizeof(*it));
    it->group = (uint8_t)group;
    switch (group) {
    case 0:
        for (i = 0; i < nv; ++i)
            if (mbs_ip_unicast_valid(vendor[i]))
                add_range(it, vendor[i], 1U, 0);
        for (i = 0; i < nh; ++i) {
            uint32_t base = hint_ips[i] & 0xFFFFFF00UL;
            int dup = 0;
            if (!mbs_ip_unicast_valid(hint_ips[i]))
                continue;
            for (j = 0; j < it->n; ++j)
                if (it->r[j].block24 && it->r[j].first == base)
                    dup = 1;
            if (!dup)
                add_range(it, base, 254U, 1);
        }
        break;
    case 1:
        add_range(it, MBS_IP(169, 254, 1, 0), 254UL * 256UL, 0); /* 169.254.1.0 - 169.254.254.255 */
        break;
    case 2:
        add_range(it, MBS_IP(192, 168, 0, 0), 2UL * 254UL, 1);
        break;
    case 3:
        add_range(it, MBS_IP(10, 0, 0, 0), 2UL * 254UL, 1);
        add_range(it, MBS_IP(10, 1, 1, 0), 254UL, 1);
        add_range(it, MBS_IP(10, 10, 10, 0), 254UL, 1);
        break;
    case 4:
        add_range(it, MBS_IP(172, 16, 0, 0), 2UL * 254UL, 1);
        break;
    case 5: /* rest of 192.168.0.0/16 */
        add_range(it, MBS_IP(192, 168, 2, 0), 254UL * 254UL, 1);
        break;
    case 6: /* rest of 172.16.0.0/12 */
        add_range(it, MBS_IP(172, 16, 2, 0), 4094UL * 254UL, 1);
        break;
    case 7: /* rest of 10.0.0.0/8 minus the P3 blocks */
        add_range(it, MBS_IP(10, 0, 2, 0), 255UL * 254UL, 1);
        add_range(it, MBS_IP(10, 1, 2, 0), 2312UL * 254UL, 1);
        add_range(it, MBS_IP(10, 10, 11, 0), 62965UL * 254UL, 1);
        break;
    default:
        break;
    }
}

uint32_t mbs_cand_get(const MbsCand *it, uint32_t idx)
{
    unsigned i;
    for (i = 0; i < it->n; ++i) {
        if (idx < it->r[i].count) {
            if (it->r[i].block24)
                return it->r[i].first + (idx / 254U) * 256U + 1U + (idx % 254U);
            return it->r[i].first + idx;
        }
        idx -= it->r[i].count;
    }
    return 0U;
}

/* ------------------------------------------------------------------------ */
/* board address choice                                                      */
/* ------------------------------------------------------------------------ */

static int board_ok(uint32_t b, uint32_t dev, uint32_t mask)
{
    uint32_t host = b & ~mask;
    if (b == dev || !mbs_ip_unicast_valid(b) || (b & mask) != (dev & mask))
        return 0;
    if (host == 0U || host == ~mask)
        return 0; /* network or broadcast address of the assumed subnet */
    if (mbs_ip_link_local(b) &&
        (b < MBS_IP(169, 254, 1, 0) || b > MBS_IP(169, 254, 254, 255)))
        return 0;
    return 1;
}

unsigned mbs_choose_board(uint32_t dev_ip, uint32_t known_mask, uint32_t *out, unsigned max)
{
    /* Flip the lowest bits first: dev^3 stays in the same /30 (the only usable
     * partner there), dev^1 in the same /31../29, then plain neighbours. */
    uint32_t cand[7];
    uint32_t mask;
    unsigned i, j, n = 0;

    if (known_mask != 0U)
        mask = known_mask;
    else if (mbs_ip_link_local(dev_ip))
        mask = mbs_prefix_to_mask(16);
    else
        mask = mbs_prefix_to_mask(24);
    cand[0] = dev_ip ^ 3U;
    cand[1] = dev_ip ^ 1U;
    cand[2] = dev_ip ^ 2U;
    cand[3] = dev_ip + 1U;
    cand[4] = dev_ip - 1U;
    cand[5] = dev_ip + 2U;
    cand[6] = dev_ip - 2U;
    for (i = 0; i < 7U && n < max; ++i) {
        int dup = 0;
        if (!board_ok(cand[i], dev_ip, mask))
            continue;
        for (j = 0; j < n; ++j)
            if (out[j] == cand[i])
                dup = 1;
        if (!dup)
            out[n++] = cand[i];
    }
    return n;
}

uint32_t mbs_choose_mask(uint32_t board_ip, const uint32_t *peer_ips, unsigned n,
                         uint32_t known_mask)
{
    static const unsigned prefixes[3] = {24U, 16U, 8U};
    unsigned p, i;
    if (known_mask != 0U)
        return known_mask;
    if (mbs_ip_link_local(board_ip))
        return mbs_prefix_to_mask(16);
    for (p = 0; p < 3U; ++p) {
        uint32_t m = mbs_prefix_to_mask(prefixes[p]);
        int all = 1;
        for (i = 0; i < n; ++i)
            if ((peer_ips[i] & m) != (board_ip & m))
                all = 0;
        if (all)
            return m;
    }
    return mbs_prefix_to_mask(8);
}

/* ------------------------------------------------------------------------ */
/* Modbus TCP                                                                */
/* ------------------------------------------------------------------------ */

uint16_t mbs_mb_build_read(uint8_t adu[12], uint16_t tid, uint8_t unit, uint8_t fc,
                           uint16_t addr, uint16_t qty)
{
    wr16(adu, tid);
    wr16(adu + 2, 0);
    wr16(adu + 4, 6);
    adu[6] = unit;
    adu[7] = fc;
    wr16(adu + 8, addr);
    wr16(adu + 10, qty);
    return 12;
}

uint16_t mbs_mb_build_devid(uint8_t adu[11], uint16_t tid, uint8_t unit,
                            uint8_t read_code, uint8_t object_id)
{
    wr16(adu, tid);
    wr16(adu + 2, 0);
    wr16(adu + 4, 5);
    adu[6] = unit;
    adu[7] = 0x2B;
    adu[8] = 0x0E;
    adu[9] = read_code;
    adu[10] = object_id;
    return 11;
}

static int exception_valid(uint8_t code)
{
    return (code >= 1U && code <= 8U) || code == 0x0AU || code == 0x0BU;
}

/* Common header check. Returns -1 invalid, 0 need more, 1 complete (info filled). */
static int mb_frame(const uint8_t *buf, uint16_t len, uint16_t tid, uint8_t unit,
                    MbsMbInfo *info)
{
    uint16_t L;
    if (len >= 2U && rd16(buf) != tid)
        return -1;
    if (len >= 4U && rd16(buf + 2) != 0U)
        return -1;
    if (len < 7U)
        return 0;
    L = rd16(buf + 4);
    if (L < 3U || L > 254U)
        return -1;
    if (len < (uint16_t)(6U + L))
        return 0;
    info->unit = buf[6];
    info->fc = buf[7];
    info->exception = 0;
    info->unit_mismatch = (uint8_t)(buf[6] != unit);
    info->frame_len = (uint16_t)(6U + L);
    return 1;
}

int mbs_mb_check_read(const uint8_t *buf, uint16_t len, uint16_t tid, uint8_t unit,
                      uint8_t fc, uint16_t qty, MbsMbInfo *info)
{
    MbsMbInfo local;
    uint16_t L;
    int r;
    if (info == NULL)
        info = &local;
    memset(info, 0, sizeof(*info));
    r = mb_frame(buf, len, tid, unit, info);
    if (r < 0)
        return MBS_MB_INVALID;
    if (r == 0)
        return MBS_MB_NEED_MORE;
    L = rd16(buf + 4);
    if (buf[7] == (uint8_t)(fc | 0x80U)) {
        if (L != 3U || !exception_valid(buf[8]))
            return MBS_MB_INVALID;
        info->exception = buf[8];
        return MBS_MB_EXCEPTION;
    }
    if (buf[7] == fc && qty != 0U && qty <= 125U &&
        L == (uint16_t)(3U + 2U * qty) && buf[8] == (uint8_t)(2U * qty))
        return MBS_MB_OK;
    return MBS_MB_INVALID;
}

int mbs_mb_check_devid(const uint8_t *buf, uint16_t len, uint16_t tid, uint8_t unit,
                       MbsMbInfo *info)
{
    MbsMbInfo local;
    uint16_t L, off, end;
    unsigned k, objects;
    int r;
    if (info == NULL)
        info = &local;
    memset(info, 0, sizeof(*info));
    r = mb_frame(buf, len, tid, unit, info);
    if (r < 0)
        return MBS_MB_INVALID;
    if (r == 0)
        return MBS_MB_NEED_MORE;
    L = rd16(buf + 4);
    if (buf[7] == 0xABU) {
        if (L != 3U || !exception_valid(buf[8]))
            return MBS_MB_INVALID;
        info->exception = buf[8];
        return MBS_MB_EXCEPTION;
    }
    if (buf[7] != 0x2BU || L < 8U || buf[8] != 0x0EU)
        return MBS_MB_INVALID;
    objects = buf[13];
    off = 14;
    end = (uint16_t)(6U + L);
    for (k = 0; k < objects; ++k) {
        if ((uint32_t)off + 2U > end)
            return MBS_MB_INVALID;
        off = (uint16_t)(off + 2U + buf[off + 1U]);
        if (off > end)
            return MBS_MB_INVALID;
    }
    return off == end ? MBS_MB_OK : MBS_MB_INVALID;
}

static void copy_text(char *dst, size_t cap, const uint8_t *src, size_t n)
{
    size_t i, m = 0;
    if (dst == NULL || cap == 0U)
        return;
    for (i = 0; i < n && m + 1U < cap; ++i)
        if (src[i] >= 0x20U && src[i] < 0x7FU)
            dst[m++] = (char)src[i];
    dst[m] = '\0';
}

void mbs_mb_parse_devid(const uint8_t *buf, uint16_t len, char *vendor, size_t vcap,
                        char *product, size_t pcap, char *revision, size_t rcap)
{
    uint16_t off = 14;
    unsigned k, objects;
    if (len < 14U)
        return;
    objects = buf[13];
    for (k = 0; k < objects && (uint32_t)off + 2U <= len; ++k) {
        uint8_t id = buf[off], l = buf[off + 1U];
        if ((uint32_t)off + 2U + l > len)
            break;
        if (id == 0U)
            copy_text(vendor, vcap, buf + off + 2U, l);
        else if (id == 1U)
            copy_text(product, pcap, buf + off + 2U, l);
        else if (id == 2U)
            copy_text(revision, rcap, buf + off + 2U, l);
        off = (uint16_t)(off + 2U + l);
    }
}
