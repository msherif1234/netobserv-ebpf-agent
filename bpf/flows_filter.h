/*
    rule based filter to filter out packets not of interest to users.
*/

#ifndef __FLOWS_FILTER_H__
#define __FLOWS_FILTER_H__

#include "utils.h"

// remove the comment below to enable debug prints
//#define ENABLE_BPF_PRINTK
#ifdef ENABLE_BPF_PRINTK
#define BPF_PRINTK(fmt, args...) bpf_printk(fmt, ##args)
#else
#define BPF_PRINTK(fmt, args...)
#endif

static __always_inline int is_zero_ip(u8 *ip, u8 len) {
    for (int i = 0; i < len; i++) {
        if (ip[i] != 0) {
            BPF_PRINTK("ip not zero ip[%d]:%d\n", i, ip[i]);
            return 0;
        }
    }
    return 1;
}

static __always_inline int is_equal_ip(u8 *ip1, u8 *ip2, u8 len) {
    for (int i = 0; i < len; i++) {
        if (ip1[i] != ip2[i]) {
            BPF_PRINTK("ip mismatched ip1[%d]:%d not equal to ip2[%d]:%d\n", i, ip1[i], i, ip2[i]);
            return 0;
        }
    }
    return 1;
}

static __always_inline int do_flow_filter_lookup(flow_id *id, struct filter_key_t *key,
                                                 filter_action *action, u8 len, u8 offset) {
    int result = 0;

    struct filter_value_t *rule = (struct filter_value_t *)bpf_map_lookup_elem(&filter_map, key);

    if (rule) {
        BPF_PRINTK("rule found\n");
        result++;
        if (rule->action != MAX_FILTER_ACTIONS) {
            BPF_PRINTK("action matched: %d\n", rule->action);
            *action = rule->action;
            result++;
        }

        if (rule->protocol != 0) {
            if (rule->protocol == id->transport_protocol) {
                BPF_PRINTK("protocol matched\n");
                result++;
                switch (rule->protocol) {
                case IPPROTO_TCP:
                case IPPROTO_UDP:
                case IPPROTO_SCTP:
                    // dstPort matching
                    if (rule->dstPortStart != 0 && rule->dstPortEnd == 0) {
                        if (rule->dstPortStart == id->dst_port) {
                            BPF_PRINTK("dstPortStart matched\n");
                            result++;
                        } else {
                            result = 0;
                            goto end;
                        }
                    } else if (rule->dstPortStart != 0 && rule->dstPortEnd != 0) {
                        if (rule->dstPortStart <= id->dst_port &&
                            id->dst_port <= rule->dstPortEnd) {
                            BPF_PRINTK("dstPortStart and dstPortEnd matched\n");
                            result++;
                        } else {
                            result = 0;
                            goto end;
                        }
                    }
                    // srcPort matching
                    if (rule->srcPortStart != 0 && rule->srcPortEnd == 0) {
                        if (rule->srcPortStart == id->src_port) {
                            BPF_PRINTK("srcPortStart matched\n");
                            result++;
                        } else {
                            result = 0;
                            goto end;
                        }
                    } else if (rule->srcPortStart != 0 && rule->srcPortEnd != 0) {
                        if (rule->srcPortStart <= id->src_port &&
                            id->src_port <= rule->srcPortEnd) {
                            BPF_PRINTK("srcPortStart and srcPortEnd matched\n");
                            result++;
                        } else {
                            result = 0;
                            goto end;
                        }
                    }
                    // Generic port matching check for either src or dst port
                    if (rule->portStart != 0 && rule->portEnd == 0) {
                        if (rule->portStart == id->src_port || rule->portStart == id->dst_port) {
                            BPF_PRINTK("portStart matched\n");
                            result++;
                        } else {
                            result = 0;
                            goto end;
                        }
                    } else if (rule->portStart != 0 && rule->portEnd != 0) {
                        if ((rule->portStart <= id->src_port && id->src_port <= rule->portEnd) ||
                            (rule->portStart <= id->dst_port && id->dst_port <= rule->portEnd)) {
                            BPF_PRINTK("portStart and portEnd matched\n");
                            result++;
                        } else {
                            result = 0;
                            goto end;
                        }
                    }
                    break;
                case IPPROTO_ICMP:
                case IPPROTO_ICMPV6:
                    if (rule->icmpType != 0) {
                        if (rule->icmpType == id->icmp_type) {
                            BPF_PRINTK("icmpType matched\n");
                            result++;
                        } else {
                            result = 0;
                            goto end;
                        }
                        if (rule->icmpCode != 0) {
                            if (rule->icmpCode == id->icmp_code) {
                                BPF_PRINTK("icmpCode matched\n");
                                result++;
                            } else {
                                result = 0;
                                goto end;
                            }
                        }
                    }
                    break;
                }
            } else {
                result = 0;
                goto end;
            }
        }

        if (!is_zero_ip(rule->ip, len)) {
            // for Ingress side we can filter using dstIP and for Egress side we can filter using srcIP
            if (id->direction == INGRESS) {
                if (is_equal_ip(rule->ip, id->dst_ip + offset, len)) {
                    BPF_PRINTK("dstIP matched\n");
                    result++;
                } else {
                    result = 0;
                    goto end;
                }
            } else {
                if (is_equal_ip(rule->ip, id->src_ip + offset, len)) {
                    BPF_PRINTK("srcIP matched\n");
                    result++;
                } else {
                    result = 0;
                    goto end;
                }
            }
        }

        if (rule->direction != MAX_DIRECTION) {
            if (rule->direction == id->direction) {
                BPF_PRINTK("direction matched\n");
                result++;
            } else {
                result = 0;
                goto end;
            }
        }
    }
end:
    BPF_PRINTK("result: %d action %d\n", result, *action);
    return result;
}

static __always_inline int flow_filter_setup_lookup_key(flow_id *id, struct filter_key_t *key,
                                                        u8 *len, u8 *offset, bool use_src_ip) {

    if (id->eth_protocol == ETH_P_IP) {
        *len = sizeof(u32);
        *offset = sizeof(ip4in6);
        if (use_src_ip) {
            __builtin_memcpy(key->ip_data, id->src_ip + *offset, *len);
        } else {
            __builtin_memcpy(key->ip_data, id->dst_ip + *offset, *len);
        }
        key->prefix_len = 32;
    } else if (id->eth_protocol == ETH_P_IPV6) {
        *len = IP_MAX_LEN;
        *offset = 0;
        if (use_src_ip) {
            __builtin_memcpy(key->ip_data, id->src_ip + *offset, *len);
        } else {
            __builtin_memcpy(key->ip_data, id->dst_ip + *offset, *len);
        }
        key->prefix_len = 128;
    } else {
        return -1;
    }
    return 0;
}

/*
 * check if the flow match filter rule and return >= 1 if the flow is to be dropped
 */
static __always_inline int is_flow_filtered(flow_id *id, filter_action *action) {
    struct filter_key_t key;
    u8 len, offset;
    int result = 0;

    __builtin_memset(&key, 0, sizeof(key));
    *action = MAX_FILTER_ACTIONS;

    // Lets do first CIDR match using srcIP.
    result = flow_filter_setup_lookup_key(id, &key, &len, &offset, true);
    if (result < 0) {
        return result;
    }

    result = do_flow_filter_lookup(id, &key, action, len, offset);
    // we have a match so return
    if (result > 0) {
        return result;
    }

    // if we can't find a match then Lets do second CIDR match using dstIP.
    result = flow_filter_setup_lookup_key(id, &key, &len, &offset, false);
    if (result < 0) {
        return result;
    }

    return do_flow_filter_lookup(id, &key, action, len, offset);
}

#endif //__FLOWS_FILTER_H__
