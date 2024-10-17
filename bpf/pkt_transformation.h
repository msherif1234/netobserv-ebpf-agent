/*
 * Packets Transformations tracker eBPF hooks.
 */

#ifndef __PKT_TRANSFORMATION_H__
#define __PKT_TRANSFORMATION_H__

#include "utils.h"

struct namespaced_flow_t {
    u64 saddr[2];
    u64 daddr[2];
    u16 sport;
    u16 dport;
    u32 netns;
    u32 zone_id;
};

static inline void invert_flow(struct namespaced_flow_t *flow) {
    u64 tmp = 0;
    tmp = flow->sport;
    flow->sport = flow->dport;
    flow->dport = tmp;

    tmp = flow->saddr[0];
    flow->saddr[0] = flow->daddr[0];
    flow->daddr[0] = tmp;

    tmp = flow->saddr[1];
    flow->saddr[1] = flow->daddr[1];
    flow->daddr[1] = tmp;
}

static inline void parse_tuple(struct nf_conntrack_tuple *t, struct namespaced_flow_t *flow) {
    flow->sport = bpf_ntohs(t->src.u.all);
    flow->dport = bpf_ntohs(t->dst.u.all);

    bpf_probe_read(&flow->saddr, sizeof(flow->saddr), &t->src.u3.all);
    bpf_probe_read(&flow->daddr, sizeof(flow->daddr), &t->dst.u3.all);
}

static inline int trace_nat_manip_pkt(struct nf_conn *ct, struct sk_buff *skb) {
    struct namespaced_flow_t orig, reply;
    struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
    u32 zone_id;

    if (!enable_pkt_transformation_tracking) {
        return 0;
    }
    bpf_probe_read(&tuplehash, sizeof(tuplehash), &ct->tuplehash);

    bpf_probe_read(&orig.zone_id, sizeof(zone_id), &ct->zone.id);
    bpf_probe_read(&reply.zone_id, sizeof(zone_id), &ct->zone.id);

    struct nf_conntrack_tuple *orig_tuple = &tuplehash[IP_CT_DIR_ORIGINAL].tuple;
    struct nf_conntrack_tuple *reply_tuple = &tuplehash[IP_CT_DIR_REPLY].tuple;

    parse_tuple(orig_tuple, &orig);
    parse_tuple(reply_tuple, &reply);

    invert_flow(&orig);
    invert_flow(&reply);

    BPF_PRINTK("org_flow: %d.%d.%d.%d:%u -> %d.%d.%d.%d:%u zoneId %d\n", orig.saddr[0] & 0xFF,
               (orig.saddr[0] >> 8) & 0xFF, (orig.saddr[0] >> 16) & 0xFF,
               (orig.saddr[0] >> 24) & 0xFF, orig.sport, orig.daddr[0] & 0xFF,
               (orig.daddr[0] >> 8) & 0xFF, (orig.daddr[0] >> 16) & 0xFF,
               (orig.daddr[0] >> 24) & 0xFF, orig.dport, orig.zone_id);

    BPF_PRINTK("reply_flow: %d.%d.%d.%d:%u -> %d.%d.%d.%d:%u zoneId %d\n", reply.saddr[0] & 0xFF,
               (reply.saddr[0] >> 8) & 0xFF, (reply.saddr[0] >> 16) & 0xFF,
               (reply.saddr[0] >> 24) & 0xFF, reply.sport, reply.daddr[0] & 0xFF,
               (reply.daddr[0] >> 8) & 0xFF, (reply.daddr[0] >> 16) & 0xFF,
               (reply.daddr[0] >> 24) & 0xFF, reply.dport, reply.zone_id);
    return 0;
}

SEC("kprobe/nf_nat_manip_pkt")
int BPF_KPROBE(track_nat_manip_pkt) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct nf_conn *ct = (struct nf_conn *)PT_REGS_PARM2(ctx);

    return trace_nat_manip_pkt(ct, skb);
}

#endif /* __PKT_TRANSFORMATION_H__ */