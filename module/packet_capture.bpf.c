// packet_capture.bpf.c
// eBPF (TC, clsact ingress): разбор Ethernet/IP/TCP/UDP и отправка
// packet_event_t в ring buffer. Пакеты не копируются целиком — только метаданные.
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

struct packet_event_t {
    u64 ts_ns;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 length;
    u8  protocol;
    u8  tcp_flags;
};

BPF_RINGBUF_OUTPUT(events, 16);   // ring buffer, 16 страниц

int capture(struct __sk_buff *skb) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    struct packet_event_t evt = {};
    evt.ts_ns    = bpf_ktime_get_ns();
    evt.saddr    = ip->saddr;
    evt.daddr    = ip->daddr;
    evt.protocol = ip->protocol;
    evt.length   = bpf_ntohs(ip->tot_len);

    // L4 считаем сразу после 20-байтного IP-заголовка
    // (без IP-опций — типичный случай для IoT-трафика)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        evt.sport     = bpf_ntohs(tcp->source);
        evt.dport     = bpf_ntohs(tcp->dest);
        evt.tcp_flags = (tcp->fin)      | (tcp->syn << 1) |
                        (tcp->rst << 2) | (tcp->psh << 3) |
                        (tcp->ack << 4) | (tcp->urg << 5);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        evt.sport = bpf_ntohs(udp->source);
        evt.dport = bpf_ntohs(udp->dest);
    }

    events.ringbuf_output(&evt, sizeof(evt), 0);
    return TC_ACT_OK;   // пропускаем пакет дальше — только наблюдаем
}
