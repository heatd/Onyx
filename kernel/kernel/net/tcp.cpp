/*
 * Copyright (c) 2020 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdint.h>

#include <onyx/err.h>
#include <onyx/mm/slab.h>
#include <onyx/net/tcp.h>
#include <onyx/poll.h>
#include <onyx/random.h>

#include <uapi/tcp.h>

socket_table tcp_table;

const inet_proto tcp_proto{"tcp", &tcp_table};

static inline inetsum_t tcp_data_csum(inetsum_t r, struct packetbuf *pbf)
{
    for (u8 i = 1; i < pbf->nr_vecs; i++)
    {
        struct page_iov *iov = &pbf->page_vec[i];
        u8 *ptr = ((u8 *) PAGE_TO_VIRT(iov->page)) + iov->page_off;
        r = __ipsum_unfolded(ptr, iov->length, r);
    }

    return r;
}

u16 tcpv4_calculate_checksum(const tcp_header *header, u16 packet_length, struct packetbuf *pbf,
                             uint32_t srcip, u32 dstip, bool calc_data)
{
    u32 proto = ((packet_length + IPPROTO_TCP) << 8);
    u16 buf[2];
    memcpy(&buf, &proto, sizeof(proto));

    inetsum_t r = __ipsum_unfolded(&srcip, sizeof(srcip), 0);
    r = __ipsum_unfolded(&dstip, sizeof(dstip), r);
    r = __ipsum_unfolded(buf, sizeof(buf), r);

    if (calc_data)
    {
        r = __ipsum_unfolded(header, pbf->tail - pbf->data, r);
        r = tcp_data_csum(r, pbf);
    }

    return ipsum_fold(r);
}

u16 tcpv6_calculate_checksum(const tcp_header *header, u16 packet_length, struct packetbuf *pbf,
                             const in6_addr &srcip, const in6_addr &dstip, bool calc_data)
{
    u32 proto = htonl(IPPROTO_TCP);
    u32 pseudo_len = htonl(packet_length);

    inetsum_t r = __ipsum_unfolded(&srcip, sizeof(srcip), 0);
    r = __ipsum_unfolded(&dstip, sizeof(dstip), r);
    r = __ipsum_unfolded(&pseudo_len, sizeof(pseudo_len), r);
    r = __ipsum_unfolded(&proto, sizeof(proto), r);
    assert(header->checksum == 0);

    if (calc_data)
    {
        r = __ipsum_unfolded(header, pbf->tail - pbf->data, r);
        r = tcp_data_csum(r, pbf);
    }

    return ipsum_fold(r);
}

#define TCP_SOCK(sock) ((struct tcp_socket *) (sock))

/**
 * @brief Calculates the TCP checksum
 *
 * @tparam domain Domain of the underlying L3 protocol
 * @param header TCP header
 * @param len Length of the packet
 * @param src Src address
 * @param dest Dest address
 * @param do_rest_of_packet True if we need to checksum all of the packet (instead of relying on
 *                          offloading)
 * @return uint16_t The internet checksum
 */
template <int domain>
uint16_t tcp_calculate_checksum(const tcp_header *header, uint16_t len, struct packetbuf *pbf,
                                const inet_route::addr &src, const inet_route::addr &dest,
                                bool do_rest_of_packet = true)
{
    uint16_t result = 0;
    if constexpr (domain == AF_INET6)
        result = tcpv6_calculate_checksum(header, len, pbf, src.in6, dest.in6, do_rest_of_packet);
    else
        result = tcpv4_calculate_checksum(header, len, pbf, src.in4.s_addr, dest.in4.s_addr,
                                          do_rest_of_packet);

    // Checksum offloading needs an unfolded checksum
    return do_rest_of_packet ? result : ~result;
}

#define TCP_MAKE_DATA_OFF(off) (off << TCP_DATA_OFFSET_SHIFT)

static struct slab_cache *tcp_cache;
extern const struct socket_ops tcp_ops;

static void tcp_init_sock(struct tcp_socket *sock)
{
    sock->proto_info = &tcp_proto;
    sock->sock_ops = &tcp_ops;
    init_wait_queue_head(&sock->conn_wq);
    sock->rcv_wnd_shift = 0;
    sock->snd_wnd_shift = 0;
    sock->retrans_active = false;
    sock->retransmit_try = 0;
    sock->mss = 0;
    sock->rcv_wnd = sock->snd_wnd = 0;
    sock->retrans_pending = 0;
    sock->state = TCP_STATE_CLOSED;
    INIT_LIST_HEAD(&sock->output_queue);
    INIT_LIST_HEAD(&sock->on_wire_queue);
    INIT_LIST_HEAD(&sock->read_queue);
    sock->snd_wl1 = sock->snd_wl2 = 0;
    bst_root_initialize(&sock->out_of_order_tree);
    sock->sacking = 0;
    sock->sack_needs_send = 0;
    sock->nr_sacks = 0;
    INIT_LIST_HEAD(&sock->conn_queue);
    INIT_LIST_HEAD(&sock->accept_queue);
    sock->connqueue_len = 0;
    /* Default the send buf to 4MiB, and the rcv buf to 16MiB */
    sock->sk_sndbuf = 0x400000;
    sock->sk_rcvbuf = 0x1000000;
}

static __init void tcp_init()
{
    /* Note: We need TYPESAFE_BY_RCU to get around locking trickyness. See the big comment under
     * tcp_input_conn. We don't need a ctor because we use a well-defined pattern:
     * refcount_inc_not_zero */
    tcp_cache =
        kmem_cache_create("tcp_socket", sizeof(struct tcp_socket), alignof(struct tcp_socket),
                          SLAB_TYPESAFE_BY_RCU | SLAB_PANIC, NULL);
}

int tcp_bind(struct socket *sock, struct sockaddr *addr, socklen_t addrlen)
{
    const struct inet_proto_family *fam = TCP_SOCK(sock)->get_proto_fam();
    return fam->bind(addr, addrlen, TCP_SOCK(sock));
}

void tcp_queue_packet(struct tcp_socket *sock, struct packetbuf *pbf)
{
    list_add_tail(&pbf->list_node, &sock->output_queue);
}

/**
 * @brief Checks if we can send a packet according to Nagle's algorithm
 *
 * @param buf Packetbuf to check
 * @return True if possible, else false.
 */
static bool tcp_nagle_can_send(struct tcp_socket *sock, struct packetbuf *buf, unsigned int buflen)
{
    // Note: pending_out_packets contains the packets that await an ACK (retransmission is done on
    // this list)
    return buflen == sock->mss || list_is_empty(&sock->on_wire_queue);
}

u8 tcp_calculate_win_scale(u32 win)
{
    /* We should pick the smallest window scale that allows us to express the given window size (in
     * order to maximize window granularity) */
    return (ilog2(win - 1) + 1) - 15;
}

static size_t tcp_push_options(struct tcp_socket *sock, struct packetbuf *pbf)
{
    auto inet_hdr_len = sock->effective_domain() == AF_INET ? sizeof(ip_header) : sizeof(ip6hdr);
    sock->send_mss = sock->route_cache.nif->mtu - sizeof(tcp_header) - inet_hdr_len;
    /* If an MSS Option is not received at connection setup, TCP implementations MUST assume a
     * default send MSS of 536 (576 - 40) for IPv4 or 1220 (1280 - 60) for IPv6 (MUST-15) */
    sock->rcv_mss = sock->effective_domain() == AF_INET ? 536 : 1220;
    uint16_t our_mss = htons(sock->send_mss);
    size_t options_len = 0;

    u8 *mss_opt = (u8 *) pbf_push_header(pbf, 4);
    mss_opt[0] = TCP_OPTION_MSS;
    mss_opt[1] = 4;
    memcpy(&mss_opt[2], &our_mss, 2);
    options_len += 4;

    u8 *scale_opt = (u8 *) pbf_push_header(pbf, 3);
    scale_opt[0] = TCP_OPTION_WINDOW_SCALE;
    scale_opt[1] = 3;
    scale_opt[2] = tcp_calculate_win_scale(sock->rcv_wnd);
    options_len += 3;
    sock->rcv_wnd_shift = scale_opt[2];

    u8 *sack_opt = (u8 *) pbf_push_header(pbf, 2);
    sack_opt[0] = TCP_OPTION_SACK_PERMITTED;
    sack_opt[1] = 2;
    options_len += 2;

    if (options_len % 4)
    {
        unsigned int nops = ALIGN_TO(options_len, 4) - options_len;
        u8 *n = (u8 *) pbf_push_header(pbf, nops);
        memset(n, TCP_OPTION_NOP, nops);
        options_len += nops;
    }

    return options_len;
}

u32 tcp_select_initial_win(struct tcp_socket *tp)
{
    return tp->sk_rcvbuf - READ_ONCE(tp->sk_rmem);
}

static u32 tcp_select_win(struct tcp_socket *tp)
{
    return tp->sk_rcvbuf - READ_ONCE(tp->sk_rmem);
}

static u16 tcp_select_wsize(struct tcp_socket *tp)
{
    u32 old_win, new_win;

    new_win = tcp_select_win(tp);
    old_win = tcp_receive_window(tp);
    if (new_win < old_win)
    {
        /* The window can't shrink. So if the new window is smaller than the old one, clamp it to
         * the old one. It is what it is. */
        new_win = old_win;
    }

    tp->rcv_wup = tp->rcv_next;
    tp->rcv_wnd = new_win;
    if (unlikely(tp->rcv_wnd_shift == 0 && tp->rcv_wnd > UINT16_MAX))
        return UINT16_MAX;
    return tp->rcv_wnd >> tp->rcv_wnd_shift;
}

static int tcp_sendpbuf(struct tcp_socket *sock, struct packetbuf *pbf)
{
    int err;
    struct tcp_header *hdr;
    unsigned int segment_len = pbf_length(pbf);
    size_t header_length = sizeof(struct tcp_header);
    u16 winsize;
    u8 flags = 0;

    DCHECK(pbf->transport_header == NULL);
    if (pbf->tpi.syn)
    {
        /* We send extra options as part of a syn or synack */
        header_length += tcp_push_options(sock, pbf);
    }

#if 0
    pr_warn("segment len %u\n", segment_len);
    for (int i = 0; i < 3; i++)
        pr_warn("vec[%d]: page %p off %u len %u\n", i, pbf->page_vec[i].page,
                pbf->page_vec[i].page_off, pbf->page_vec[i].length);
#endif
    hdr = (struct tcp_header *) pbf_push_header(pbf, sizeof(struct tcp_header));
    memset(hdr, 0, sizeof(struct tcp_header));
    if (pbf->tpi.ack)
        flags |= TCP_FLAG_ACK;
    if (pbf->tpi.fin)
        flags |= TCP_FLAG_FIN;
    if (pbf->tpi.syn)
        flags |= TCP_FLAG_SYN;
    if (pbf->tpi.rst)
        flags |= TCP_FLAG_RST;
    winsize = tcp_select_wsize(sock);
    hdr->ack_number = htonl(sock->rcv_next);
    hdr->sequence_number = htonl(pbf->tpi.seq);
    hdr->data_offset_and_flags =
        htons(TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(header_length)) | flags);
    hdr->dest_port = sock->dest_addr.port;
    hdr->source_port = sock->src_addr.port;
    hdr->window_size = htons(winsize);

    if (unlikely(pbf->tpi.syn))
    {
        /* The window scale does not apply for the initial SYN, so be careful with that. Truncate it
         * temporarily to UINT16_MAX if we need to, else pass the calculated rcv_wnd */
        if (sock->rcv_wnd_shift > 0)
            hdr->window_size = sock->rcv_wnd > UINT16_MAX ? UINT16_MAX : htons(sock->rcv_wnd);
    }

    bool need_csum = true;

    if (sock->can_offload_csum(sock->route_cache.nif, pbf))
    {
        pbf->csum_offset = &hdr->checksum;
        pbf->csum_start = (unsigned char *) hdr;
        pbf->needs_csum = 1;
        need_csum = false;
    }

    hdr->checksum = call_based_on_inet2(
        sock, tcp_calculate_checksum, hdr, static_cast<uint16_t>(header_length + segment_len), pbf,
        sock->route_cache.src_addr, sock->route_cache.dst_addr, need_csum);

    iflow flow{sock->route_cache, IPPROTO_TCP, sock->effective_domain() == AF_INET6};
    if (sock->effective_domain() == AF_INET)
        err = ip::v4::send_packet(flow, pbf);
    else
        err = ip::v6::send_packet(flow, pbf);

    pbf_put_ref(pbf);
    return err;
}

static void pbf_init_tcp(struct packetbuf *pbf)
{
    memset(&pbf->tpi, 0, sizeof(pbf->tpi));
}

static u16 tcp_prepare_sacks(struct tcp_socket *sock, struct packetbuf *pbf)
{
    u16 len = 2 + sock->nr_sacks * 8;
    u32 *sack;
    u8 *sack_opt = (u8 *) pbf_push_header(pbf, 2 + sock->nr_sacks * 8);
    sack_opt[0] = TCP_OPTION_SACK;
    sack_opt[1] = 2 + sock->nr_sacks * 8;
    sack = (u32 *) &sack_opt[2];
    for (int i = sock->nr_sacks - 1; i >= 0; i--)
    {
        u32 start = htonl(sock->sacks[i].start);
        u32 end = htonl(sock->sacks[i].end);
        memcpy(&sack[i * 2], &start, sizeof(u32));
        memcpy(&sack[i * 2 + 1], &end, sizeof(u32));
    }

    if (len % 4)
    {
        u16 aligned_len = ALIGN_TO(len, 4);
        u8 *nop = (u8 *) pbf_push_header(pbf, aligned_len - len);
        memset(nop, TCP_OPTION_NOP, aligned_len - len);
        len = aligned_len;
    }

    sock->sack_needs_send = 0;
    return len;
}

static void tcp_prepare_nondata_header(struct tcp_socket *sock, struct packetbuf *pbf, u32 seq,
                                       unsigned int flags)
{
    struct tcp_header *hdr;
    u16 header_len = sizeof(struct tcp_header);
    if (sock->sack_needs_send)
        header_len += tcp_prepare_sacks(sock, pbf);

    hdr = (struct tcp_header *) pbf_push_header(pbf, sizeof(struct tcp_header));
    memset(hdr, 0, sizeof(struct tcp_header));

    hdr->ack_number = htonl(sock->rcv_next);
    hdr->sequence_number = htonl(seq);
    hdr->dest_port = sock->dest_addr.port;
    hdr->source_port = sock->src_addr.port;
    hdr->window_size = htons(tcp_select_wsize(sock));
    hdr->data_offset_and_flags =
        htons(TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(header_len)) | flags);
    bool need_csum = true;

    if (sock->can_offload_csum(sock->route_cache.nif, pbf))
    {
        pbf->csum_offset = &hdr->checksum;
        pbf->csum_start = (unsigned char *) hdr;
        pbf->needs_csum = 1;
        need_csum = false;
    }

    hdr->checksum =
        call_based_on_inet2(sock, tcp_calculate_checksum, hdr, header_len, pbf,
                            sock->route_cache.src_addr, sock->route_cache.dst_addr, need_csum);
}

static int tcp_send_segment(struct tcp_socket *sock, struct packetbuf *pbf)
{
    iflow flow{sock->route_cache, IPPROTO_TCP, sock->effective_domain() == AF_INET6};
    if (sock->effective_domain() == AF_INET)
        return ip::v4::send_packet(flow, pbf);
    else
        return ip::v6::send_packet(flow, pbf);
}

int tcp_send_ack(struct tcp_socket *sock)
{
    int err;
    struct packetbuf *pbf = pbf_alloc(GFP_ATOMIC);
    if (!pbf)
        return -ENOMEM;
    if (!pbf_allocate_space(pbf, MAX_TCP_HEADER_LENGTH))
    {
        pbf_free(pbf);
        return -ENOMEM;
    }

    pbf_reserve_headers(pbf, MAX_TCP_HEADER_LENGTH);
    pbf_init_tcp(pbf);
    pbf->tpi.ack = 1;

    tcp_prepare_nondata_header(sock, pbf, sock->snd_next, TCP_FLAG_ACK);
    err = tcp_send_segment(sock, pbf);
    pbf_put_ref(pbf);
    if (!err)
        sock->delack_pending = 0;
    return err;
}

static void tcp_start_retransmit_timer(struct tcp_socket *sock, hrtime_t timeout);

static void tcp_retransmit_segments(struct tcp_socket *sock)
{
    struct packetbuf *pbf;
    if (sock->retransmit_try == tcp_retransmission_max)
    {
        /* Send a RST and give up */
        // if (ESTABLISHED (or later??))
        // send_reset();
        tcp_set_state(sock, TCP_STATE_CLOSE_WAIT);
        wait_queue_wake_all(&sock->rx_wq);
        sock->retrans_active = false;
        return;
    }

    /* Go through pending out, resubmit, and reschedule a new timer */
    list_for_each_entry (pbf, &sock->on_wire_queue, list_node)
    {
        struct packetbuf *clone = packetbuf_clone(pbf);
        if (!clone)
            return;

        tcp_sendpbuf(sock, clone);
    }

    hrtime_t timeout = 200 * NS_PER_MS;
    sock->retransmit_try++;
    for (int i = 0; i < sock->retransmit_try; i++)
        timeout *= 2;
    tcp_start_retransmit_timer(sock, timeout);
}

static void tcp_do_retransmit(struct tcp_socket *sock)
{
    sock->socket_lock.lock_bh();
    if (!sock->socket_lock.is_ours())
    {
        sock->retrans_pending = 1;
        sock->proto_needs_work = true;
    }
    else
        tcp_retransmit_segments(sock);
    sock->socket_lock.unlock_bh();
}

static void tcp_out_timeout(clockevent *ev)
{
    tcp_socket *t = (tcp_socket *) ev->priv;
    tcp_do_retransmit(t);
}

void tcp_start_retransmit_timer(struct tcp_socket *sock, hrtime_t timeout)
{
    sock->retransmit_timer.callback = tcp_out_timeout;
    sock->retransmit_timer.flags = 0;
    sock->retransmit_timer.deadline = clocksource_get_time() + timeout;
    sock->retransmit_timer.priv = sock;
    timer_queue_clockevent(&sock->retransmit_timer);
}

void tcp_start_retransmit(struct tcp_socket *sock)
{
    /* Socket lock must be held */
    if (sock->retrans_active)
        return;
    sock->retransmit_try = 0;
    tcp_start_retransmit_timer(sock, 200 * NS_PER_MS);
    sock->retrans_active = true;
}

void tcp_stop_retransmit(struct tcp_socket *sock)
{
    sock->retransmit_try = 0;
    if (sock->retrans_active)
        timer_cancel_event(&sock->retransmit_timer);
    sock->retrans_active = false;
    sock->retrans_pending = 0;
}

static bool tcp_snd_wnd_check(struct tcp_socket *tp, struct packetbuf *pbf)
{
    CHECK(pbf->tpi.seq == 0);
    u32 end = tp->snd_next + tcp_pbf_end_seq(pbf);
    return !after(end, tcp_wnd_end(tp));
}

#define TCP_OUTPUT_NO_OUTPUT 1

int tcp_output(struct tcp_socket *sock)
{
    int err = TCP_OUTPUT_NO_OUTPUT;
    struct packetbuf *pbf, *next;
    list_for_each_entry_safe (pbf, next, &sock->output_queue, list_node)
    {
        unsigned int len = pbf_length(pbf);
        // Need to stop: the window doesn't allow us to send data
        if (len > 0 && !tcp_snd_wnd_check(sock, pbf))
            break;

        // If we're on nagle and nagle doesn't allow us to send, stop sending
        if (sock->nagle_enabled && !tcp_nagle_can_send(sock, pbf, len))
            break;

        /* We're outputting this segment - assign snd_next and bump it */
        pbf->tpi.seq = sock->snd_next;
        sock->snd_next += pbf->tpi.seq_len;

        struct packetbuf *clone = packetbuf_clone(pbf);
        if (!clone)
            return -ENOBUFS;
        err = tcp_sendpbuf(sock, clone);
        if (err)
            break;
        list_remove(&pbf->list_node);
        list_add_tail(&pbf->list_node, &sock->on_wire_queue);
    }

    if (!err)
        tcp_start_retransmit(sock);
    return err;
}

static int tcp_wait_conn(struct tcp_socket *sock)
{
    /* TODO: TIMEOUT! */
    return wait_for_event_socklocked_interruptible_2(&sock->rx_wq,
                                                     sock->state != TCP_STATE_SYN_SENT, sock);
}

int tcp_start_connection(struct tcp_socket *sock, int flags)
{
    int err;
    sock->snd_next = sock->snd_una = arc4random();

    auto fam = sock->get_proto_fam();
    auto result = fam->route(sock->src_addr, sock->dest_addr, sock->domain);
    if (result.has_error())
        return result.error();

    sock->route_cache = result.value();

    if (sock->route_cache.flags & (INET4_ROUTE_FLAG_BROADCAST | INET4_ROUTE_FLAG_MULTICAST))
    {
        // Not a valid TCP connection
        // Linux seems to return ENETUNREACH here.
        return -ENETUNREACH;
    }

    sock->route_cache_valid = 1;
    sock->snd_wnd = UINT16_MAX;
    sock->rcv_wnd = tcp_select_initial_win(sock);

    struct packetbuf *pbf = pbf_alloc(GFP_KERNEL);
    if (!pbf)
        return -ENOBUFS;

    if (!pbf_allocate_space(pbf, MAX_TCP_HEADER_LENGTH))
    {
        pbf_free(pbf);
        return -ENOBUFS;
    }

    pbf_reserve_headers(pbf, MAX_TCP_HEADER_LENGTH);
    pbf->tpi.seq = sock->snd_next++;
    pbf->tpi.seq_len = 1;
    pbf->tpi.ack = pbf->tpi.fin = pbf->tpi.rst = 0;
    pbf->tpi.syn = 1;
    tcp_queue_packet(sock, pbf);
    tcp_set_state(sock, TCP_STATE_SYN_SENT);

    err = tcp_output(sock);
    CHECK(err != TCP_OUTPUT_NO_OUTPUT);
    if (err < 0)
        return err;

    if (flags & O_NONBLOCK)
        return -EINPROGRESS;

    err = tcp_wait_conn(sock);
    if (!err)
    {
        if (sock->state != TCP_STATE_ESTABLISHED)
            err = -ECONNREFUSED;
    }

    return 0;
}

int tcp_connect(struct socket *sock_, struct sockaddr *addr, socklen_t addrlen, int flags)
{
    struct tcp_socket *sock = TCP_SOCK(sock_);
    if (!sock->bound)
    {
        auto fam = sock->get_proto_fam();
        int st = fam->bind_any(sock);
        if (st < 0)
            return st;
    }

    if (sock->state != TCP_STATE_CLOSED)
        return sock->state == TCP_STATE_SYN_SENT ? -EALREADY : -EISCONN;

    if (!sock->validate_sockaddr_len_pair(addr, addrlen))
        return -EINVAL;

    auto [dst, addr_domain] = sockaddr_to_isa(addr);

    bool on_ipv4_mode = addr_domain == AF_INET && sock->domain == AF_INET6;

    sock->dest_addr = dst;
    sock->ipv4_on_inet6 = on_ipv4_mode;
    return tcp_start_connection(sock, flags);
}

int tcp_getsockname(struct socket *sock_, sockaddr *addr, socklen_t *len)
{
    struct tcp_socket *sock = TCP_SOCK(sock_);
    if (!sock->bound)
        return -EINVAL;

    sock->copy_addr_to_sockaddr(sock->src_addr, addr, len);
    return 0;
}

int tcp_getpeername(struct socket *sock_, sockaddr *addr, socklen_t *len)
{
    struct tcp_socket *sock = TCP_SOCK(sock_);
    if (tcp_state_is_fl(sock, TCPF_STATE_CLOSED))
        return -ENOTCONN;

    sock->copy_addr_to_sockaddr(sock->dest_addr, addr, len);
    return 0;
}

static void tcp_do_delack(struct tcp_socket *sock)
{
    tcp_send_ack(sock);
    if (sock->delack_active)
    {
        timer_cancel_event(&sock->delack_timer);
        sock->delack_active = 0;
    }
}

static void tcp_handle_backlog(struct socket *sock_)
{
    // For every pending segment, get its packetbuf. Then figure out packet_handling_data and ship
    // it to the proper handling functions.
    struct tcp_socket *sock = TCP_SOCK(sock_);
    struct packetbuf *pbf, *next;

    list_for_each_entry_safe (pbf, next, &sock->socket_backlog, list_node)
    {
        list_remove(&pbf->list_node);
        int err = tcp_input(sock, pbf);
        if (err)
            pr_info("drop packet %u\n", err);
        pbf_put_ref(pbf);
    }

    if (sock->proto_needs_work)
    {
        if (sock->retrans_pending)
        {
            tcp_retransmit_segments(sock);
            sock->retrans_pending = 0;
        }

        if (sock->delack_pending)
        {
            tcp_do_delack(sock);
            sock->delack_pending = 0;
        }

        if (sock->sack_needs_send)
            tcp_send_ack(sock);

        sock->proto_needs_work = false;
    }
}

short tcp_poll(struct socket *sock_, void *poll_file, short events)
{
    // TODO: Find this stuff out. It's kind of confusing and there doesn't seem
    // to be good documentation on this. Even the trusty UNIX Network Programming doesn't help...
    short avail_events = 0;
    struct tcp_socket *sock = TCP_SOCK(sock_);

    scoped_hybrid_lock g2{sock->socket_lock, sock};

    if (sock->state == tcp_state::TCP_STATE_CLOSED || sock->shutdown_state == SHUTDOWN_RDWR)
        avail_events |= POLLHUP;
    if (sock->shutdown_state & SHUTDOWN_RD)
        avail_events |= POLLIN | POLLRDNORM | POLLRDHUP;

    if (sock->state == tcp_state::TCP_STATE_LISTEN)
    {
        if (events & POLLIN)
        {
            if (!list_is_empty(&sock->accept_queue))
                avail_events |= POLLIN;
            else
                poll_wait_helper(poll_file, &sock->rx_wq);
        }

        return avail_events & events;
    }

    if (sock->state == tcp_state::TCP_STATE_SYN_SENT)
    {
        avail_events &= ~POLLOUT;
        if (events & POLLOUT)
            poll_wait_helper(poll_file, &sock->rx_wq);

        return avail_events & events;
    }

    if (events & POLLOUT)
    {
        if (!(sock->shutdown_state & SHUTDOWN_WR) && sock_may_write(sock))
            avail_events |= POLLOUT;
    }

    if (events & POLLIN)
    {
        if (!list_is_empty(&sock->read_queue))
            avail_events |= POLLIN;
        else
            poll_wait_helper(poll_file, &sock->rx_wq);
    }

    return avail_events & events;
}

/**
 * @brief Prepare segment for sending
 *
 * @param buf Packetbuf
 */
static void tcp_prepare_segment(struct tcp_socket *sock, struct packetbuf *pbf)
{
    unsigned int flags = TCP_FLAG_ACK;
    pbf_init_tcp(pbf);
    auto segment_len = pbf_length(pbf);
    pbf->tpi.seq = 0;
    pbf->tpi.seq_len = segment_len;
    pbf->tpi.ack = 1;

    if (flags & TCP_FLAG_FIN)
        pbf->tpi.seq_len++;
}

static int tcp_write_alloc(struct tcp_socket *sock);

static bool tcp_attempt_merge(struct packetbuf *pbf, struct page_frag *pf)
{
    struct page_iov *iov = &pbf->page_vec[pbf->nr_vecs - 1];

    /* Okay, we have the last page_iov. Check if we can merge it, if not, check if we can append the
     * page frag. */
    if (likely(iov->page == pf->page && iov->page_off + iov->length == pf->offset))
    {
        iov->length += pf->len;
        /* We already hold a ref, so drop the new one */
        page_unref(pf->page);
        /* And adjust the pbf data area if required */
        if (pbf->nr_vecs == 1)
        {
            pbf->tail += pf->len;
            pbf->end += pf->len;
        }
        return true;
    }

    /* TODO: We can't use the last page_iov for legacy reasons */
    if (unlikely(pbf->nr_vecs >= PBF_PAGE_IOVS - 1))
        return false;
    pbf->nr_vecs++;
    iov++;
    iov->page = pf->page;
    iov->page_off = pf->offset;
    iov->length = pf->len;
    return true;
}

static u8 *ptr_from_frag(struct page_frag *pf)
{
    return ((u8 *) PAGE_TO_VIRT(pf->page)) + pf->offset;
}

static int tcp_append_to_segment(struct tcp_socket *tp, struct packetbuf *pbf,
                                 struct iovec_iter *iter)
{
    struct iovec iov;
    unsigned int len, to_add;
    struct page_frag pf;
    int err;

    int write_space = sock_write_space(tp);
    if (write_space <= 0)
        return -EWOULDBLOCK;

    len = pbf_length(pbf);

    while (len < tp->mss)
    {
        if (iter->empty())
            break;
        if (write_space == 0)
            break;

        iov = iter->curiovec();
        to_add = min((unsigned int) iov.iov_len, (unsigned int) write_space);
        to_add = min(to_add, tp->mss - len);
        to_add = min(to_add, (unsigned int) PAGE_SIZE);

        err = page_frag_alloc(&tp->sock_pfi, to_add, GFP_KERNEL, &pf);
        if (err)
            return -ENOBUFS;

        /* Note: We cannot copy_from_iter because we don't yet know if this fragment will be valid
         */
        if (copy_from_user(ptr_from_frag(&pf), iov.iov_base, to_add) < 0)
        {
            page_unref(pf.page);
            return -EFAULT;
        }

        if (WARN_ON(!sock_charge_snd_bytes(tp, to_add)))
        {
            /* This should not happen, since the send buf cannot suddenly shrink while we hold
             * the socket lock. */
            page_unref(pf.page);
            break;
        }

        if (unlikely(!tcp_attempt_merge(pbf, &pf)))
        {
            page_unref(pf.page);
            sock_discharge_snd_bytes(tp, to_add);
            break;
        }

        pbf->total_len += pf.len;
        len += pf.len;
        write_space -= len;
        pbf->tpi.seq_len += pf.len;
        iter->advance(to_add);
    }

    return iter->empty() ? 0 : -ENOSPC;
}

static int tcp_append_write(struct tcp_socket *sock, struct iovec_iter *iter, size_t mss, int flags)
{
    struct packetbuf *pbf = NULL;
    int old_space;
    int err;

    while (!iter->empty())
    {
        if (!sock_may_write(sock))
            goto wait_for_space;
        if (list_is_empty(&sock->output_queue))
            goto alloc_segment;

        pbf = list_last_entry(&sock->output_queue, struct packetbuf, list_node);

        err = tcp_append_to_segment(sock, pbf, iter);
        if (err == -EWOULDBLOCK)
            goto wait_for_space;
        if (err != -ENOSPC)
            return err;

    alloc_segment:
        err = tcp_write_alloc(sock);
        if (err == -EWOULDBLOCK)
            goto wait_for_space;
        if (err)
            return err;
        continue;
    wait_for_space:
        if (flags & MSG_DONTWAIT)
            return -EWOULDBLOCK;
        /* Try to output */
        tcp_output(sock);
        old_space = sock_write_space(sock);
        err = wait_for_event_socklocked_interruptible_2(&sock->rx_wq,
                                                        sock_write_space(sock) > old_space, sock);
        if (err == -ERESTARTSYS)
            return err;
    }

    return 0;
}

static void tcp_pbf_dtor(struct packetbuf *pbf)
{
    sock_discharge_pbf(pbf->sock, pbf);
}

static int tcp_write_alloc(struct tcp_socket *sock)
{
    struct packetbuf *pbf = pbf_alloc_sk(GFP_KERNEL, sock, MAX_TCP_HEADER_LENGTH);
    if (!pbf)
        return -ENOBUFS;

    if (!sock_charge_pbf(sock, pbf))
    {
        /* Failed to charge write space, stop. */
        pbf_free(pbf);
        return -EAGAIN;
    }

    pbf->dtor = tcp_pbf_dtor;

    pbf_reserve_headers(pbf, MAX_TCP_HEADER_LENGTH);
    tcp_prepare_segment(sock, pbf);
    list_add_tail(&pbf->list_node, &sock->output_queue);
    return 0;
}

ssize_t tcp_sendmsg(struct socket *sock_, const msghdr *msg, int flags)
{
    int err;
    struct tcp_socket *sock = TCP_SOCK(sock_);
    if (msg->msg_name)
        return -EISCONN;

    scoped_hybrid_lock g{sock->socket_lock, sock};

    if (sock->has_sock_err())
        return sock_stream_error(sock, sock->consume_sock_err(), flags);

    if (sock->shutdown_state & SHUTDOWN_WR ||
        !tcp_state_is_fl(sock, TCPF_STATE_CLOSE_WAIT | TCPF_STATE_ESTABLISHED))
    {
        err = -EPIPE;
        if (sock->state == TCP_STATE_SYN_SENT)
        {
            err = tcp_wait_conn(sock);
            if (!err && sock->state != TCP_STATE_ESTABLISHED)
                err = -ENOTCONN;
        }

        if (err)
            return sock_stream_error(sock, err, flags);
    }

    auto len = iovec_count_length(msg->msg_iov, msg->msg_iovlen);

    if (len < 0)
        return len;

    iovec_iter iter{{msg->msg_iov, (size_t) msg->msg_iovlen}, (size_t) len, IOVEC_USER};
    err = tcp_append_write(sock, &iter, sock->mss, flags);
    if (err < 0)
        return len - iter.bytes ?: err;

    err = tcp_output(sock);
    if (err < 0)
        return len ?: err;

    return len;
}

static struct packetbuf *tcp_get_segment(struct tcp_socket *sock, int flags)
{
    int st = 0;
    struct packetbuf *buf = NULL;

    for (;;)
    {
        if (st == -ERESTARTSYS)
            goto out_err;

        if (!list_is_empty(&sock->read_queue))
        {
            buf = list_first_entry(&sock->read_queue, struct packetbuf, list_node);
            break;
        }

        if (list_is_empty(&sock->read_queue) && flags & MSG_DONTWAIT)
        {
            st = -EWOULDBLOCK;
            goto out_err;
        }

        if (list_is_empty(&sock->read_queue) && sock->shutdown_state & SHUTDOWN_RD)
            return NULL;

        st = wait_for_event_socklocked_interruptible_2(&sock->rx_wq,
                                                       !list_is_empty(&sock->read_queue), sock);
    }

    return buf;
out_err:
    return (struct packetbuf *) ERR_PTR(st);
}

static void tcp_update_rmem_window(struct tcp_socket *tp, size_t bytes_read)
{
    u32 old_win = tcp_receive_window(tp);
    u32 new_win = tcp_select_win(tp);
    if (new_win >= 2 * old_win && new_win > 0)
        tcp_send_ack(tp);
}

static ssize_t tcp_recvmsg(struct socket *sock_, msghdr *msg, int flags)
{
    size_t bytes_read = 0;
    ssize_t iovlen;
    unsigned int pbuf_len;
    struct packetbuf *pbf, *next;
    struct tcp_socket *sock = TCP_SOCK(sock_);

    iovlen = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
    if (iovlen < 0)
        return iovlen;

    iovec_iter iter{{msg->msg_iov, (size_t) msg->msg_iovlen}, (size_t) iovlen, IOVEC_USER};
    scoped_hybrid_lock g{sock_->socket_lock, sock_};

    if (sock->has_sock_err())
        return sock->consume_sock_err();

    pbf = tcp_get_segment(sock, flags);
    if (IS_ERR(pbf))
        return PTR_ERR(pbf);

    if (!pbf)
    {
        /* shutdown from our side, EOF */
        return 0;
    }

    pbuf_len = pbf_length(pbf);

    if (iovlen < pbuf_len)
        msg->msg_flags = MSG_TRUNC;

    list_for_each_entry_safe (pbf, next, &sock->read_queue, list_node)
    {
        if (iter.empty())
            break;
        ssize_t read = pbf->copy_iter(iter, flags & MSG_PEEK ? PBF_COPY_ITER_PEEK : 0);

        if (read < 0)
        {
            if (bytes_read == 0)
                bytes_read = read;
            break;
        }

        if (!(flags & MSG_PEEK))
        {
            if (pbf_length(pbf) == 0)
            {
                list_remove(&pbf->list_node);
                pbf_put_ref(pbf);
            }
        }

        bytes_read += read;
    }

    if (bytes_read > 0 && !(flags & MSG_PEEK))
    {
        /* pbfs freed, communicate the new window if required */
        tcp_update_rmem_window(sock, bytes_read);
    }

    msg->msg_controllen = 0;
    return bytes_read;
}

static bool should_send_fin(enum tcp_state state)
{
    return state == TCP_STATE_SYN_RECEIVED || state == TCP_STATE_ESTABLISHED ||
           state == TCP_STATE_CLOSE_WAIT;
}

static int tcp_send_fin(struct tcp_socket *sock)
{
    struct packetbuf *pbf = pbf_alloc(GFP_KERNEL);
    if (!pbf)
        return -ENOBUFS;

    if (!pbf_allocate_space(pbf, MAX_TCP_HEADER_LENGTH))
    {
        pbf_free(pbf);
        return -ENOBUFS;
    }

    pbf_reserve_headers(pbf, MAX_TCP_HEADER_LENGTH);
    pbf_init_tcp(pbf);
    pbf->tpi.seq = 0;
    pbf->tpi.seq_len = 1;
    pbf->tpi.ack = pbf->tpi.fin = 1;
    tcp_queue_packet(sock, pbf);
    return 0;
}

// clang-format off
static const enum tcp_state post_wr_shutdown_states[] = {
    [TCP_STATE_LISTEN] = TCP_STATE_CLOSED,
    [TCP_STATE_SYN_SENT] = TCP_STATE_CLOSED,
    [TCP_STATE_SYN_RECEIVED] = TCP_STATE_FIN_WAIT_1,
    [TCP_STATE_ESTABLISHED] = TCP_STATE_FIN_WAIT_1,
    [TCP_STATE_FIN_WAIT_1] = TCP_STATE_FIN_WAIT_1,
    [TCP_STATE_FIN_WAIT_2] = TCP_STATE_FIN_WAIT_2,
    [TCP_STATE_CLOSE_WAIT] = TCP_STATE_LAST_ACK,
    [TCP_STATE_CLOSING] = TCP_STATE_CLOSING,
    [TCP_STATE_LAST_ACK] = TCP_STATE_LAST_ACK,
    [TCP_STATE_TIME_WAIT] = TCP_STATE_CLOSED,
    [TCP_STATE_CLOSED] = TCP_STATE_CLOSED,
};

// clang-format on

static int tcp_shutdown(struct socket *sock_, int how)
{
    int err;
    struct tcp_socket *sock = TCP_SOCK(sock_);
    scoped_hybrid_lock g{sock->socket_lock, sock};

    if (how & SHUTDOWN_WR)
    {
        // Shutdown the write end
        // Set the next state and send a FIN if necessary.
        if (should_send_fin(sock->state))
        {
            err = tcp_send_fin(sock);
            if (err < 0)
                return err;
            err = tcp_output(sock);
            if (err < 0)
                return err;
        }
        tcp_set_state(sock, post_wr_shutdown_states[sock->state]);
    }

    sock->shutdown_state |= how;

    // Lets find out needs to be woken up.
    // For now, only readers need to be unblocked.
    if (how & SHUTDOWN_RD)
        wait_queue_wake_all(&sock->rx_wq);

    return 0;
}

/* In cases where we close a socket while having unread data, we send an active reset. This
 * behavior is sanctioned by RFC1122 and RFC2525. */
static void tcp_send_active_reset(struct tcp_socket *sock, gfp_t gfp)
{
    struct packetbuf *pbf = pbf_alloc(gfp);
    if (!pbf)
        return;
    if (!pbf_allocate_space(pbf, MAX_TCP_HEADER_LENGTH))
    {
        pbf_free(pbf);
        return;
    }

    pbf_reserve_headers(pbf, MAX_TCP_HEADER_LENGTH);
    pbf_init_tcp(pbf);
    tcp_prepare_nondata_header(sock, pbf, sock->snd_next, TCP_FLAG_ACK | TCP_FLAG_RST);
    tcp_send_segment(sock, pbf);
    pbf_put_ref(pbf);
}

void tcp_destroy_sock(struct tcp_socket *sock)
{
    struct packetbuf *pbf, *next;
    DCHECK(sock->dead);
    DCHECK(!sock->socket_lock.is_ours());
    tcp_stop_retransmit(sock);

    list_for_each_entry_safe (pbf, next, &sock->on_wire_queue, list_node)
    {
        list_remove(&pbf->list_node);
        pbf_free(pbf);
    }

    list_for_each_entry_safe (pbf, next, &sock->output_queue, list_node)
    {
        list_remove(&pbf->list_node);
        pbf_free(pbf);
    }

    bst_for_every_entry_delete(&sock->out_of_order_tree, pbf, struct packetbuf, bst_node)
        pbf_put_ref(pbf);

    list_for_each_entry_safe (pbf, next, &sock->read_queue, list_node)
    {
        list_remove(&pbf->list_node);
        pbf_free(pbf);
    }

    WARN_ON(sock->sk_send_queued > 0);
    if (WARN_ON(sock->sk_rmem > 0))
        pr_warn("tcp: socket with leftover sk_rmem %u\n", sock->sk_rmem);
    sock->unref();
}

void tcp_done(struct tcp_socket *sock)
{
    tcp_set_state(sock, TCP_STATE_CLOSED);
    sock->shutdown_state = SHUTDOWN_RDWR;
    if (sock->dead)
        tcp_destroy_sock(sock);
}

void tcp_done_error(struct tcp_socket *sock, int err)
{
    sock->sock_err = err;
    tcp_done(sock);
}

static void tcp_close(struct socket *sock_)
{
    struct tcp_socket *sock = TCP_SOCK(sock_);
    sock->socket_lock.lock();

    if (!list_is_empty(&sock->read_queue))
    {
        tcp_send_active_reset(sock, GFP_KERNEL);
        tcp_set_state(sock, TCP_STATE_CLOSED);
    }
    else
    {
        if (should_send_fin(sock->state))
        {
            tcp_send_fin(sock);
            tcp_output(sock);
        }

        tcp_set_state(sock, post_wr_shutdown_states[sock->state]);
    }

    if (sock->state == TCP_STATE_LISTEN)
    {
        /* LISTEN -> CLOSED Just Works */
        tcp_set_state(sock, TCP_STATE_CLOSED);
    }

    sock->dead = true;
    sock->socket_lock.unlock_sock(sock_);

    if (sock->state == TCP_STATE_CLOSED)
        tcp_destroy_sock(sock);
}

static int tcp_listen(struct socket *sock_)
{
    struct tcp_socket *sock = TCP_SOCK(sock_);
    if (sock->state != TCP_STATE_CLOSED)
        return -EINVAL;

    if (!sock->bound)
    {
        int st = sock->get_proto_fam()->bind_any(sock);

        if (st < 0)
            return -EADDRINUSE;
    }

    tcp_set_state(sock, tcp_state::TCP_STATE_LISTEN);
    return 0;
}

struct socket *tcp_accept(struct socket *sock_, int flags)
{
    struct tcp_socket *sock = TCP_SOCK(sock_);
    struct tcp_socket *new_sock;
    int err;

    sock->socket_lock.lock();
    CHECK(sock->state == TCP_STATE_LISTEN);
    err = wait_for_event_socklocked_interruptible_2(&sock->rx_wq,
                                                    !list_is_empty(&sock->accept_queue), sock);
    if (err)
    {
        sock->socket_lock.unlock();
        return NULL;
    }

    CHECK(!list_is_empty(&sock->accept_queue));
    new_sock = list_first_entry(&sock->accept_queue, struct tcp_socket, conn_queue);
    list_remove(&new_sock->conn_queue);
    sock->socket_lock.unlock();
    return new_sock;
}

static int tcp_getsockopt(struct socket *, int level, int optname, void *optval, socklen_t *optlen);
static int tcp_setsockopt(struct socket *, int level, int optname, const void *optval,
                          socklen_t optlen);

static void tcp_write_space(struct socket *sock)
{
    struct tcp_socket *tp = TCP_SOCK(sock);
    /* This looks... overeager to wake up? */
    wait_queue_wake_all(&tp->rx_wq);
}

const struct socket_ops tcp_ops = {
    .destroy = cpp_destroy<tcp_socket>,
    .listen = tcp_listen,
    .accept = tcp_accept,
    .bind = tcp_bind,
    .connect = tcp_connect,
    .sendmsg = tcp_sendmsg,
    .recvmsg = tcp_recvmsg,
    .getsockname = tcp_getsockname,
    .getpeername = tcp_getpeername,
    .shutdown = tcp_shutdown,
    .getsockopt = tcp_getsockopt,
    .setsockopt = tcp_setsockopt,
    .close = tcp_close,
    .handle_backlog = tcp_handle_backlog,
    .poll = tcp_poll,
    .write_space = tcp_write_space,
};

struct socket *tcp_create_socket(int type)
{
    struct tcp_socket *sock = (struct tcp_socket *) kmem_cache_alloc(tcp_cache, GFP_ATOMIC);
    /* Most init is done on the ctor's side, we do tcp-specific init here... What's really
     * important is that the core socket is TYPESAFE_BY_RCU. */
    if (sock)
    {
        new (sock) tcp_socket;
        tcp_init_sock(sock);
    }

    return sock;
}

static size_t tcp_push_synack_options(struct tcp_connreq *conn, struct packetbuf *pbf)
{
    size_t inet_hdr_len = conn->tc_domain == AF_INET ? sizeof(ip_header) : sizeof(ip6hdr);
    conn->tc_our_mss = conn->tc_route.nif->mtu - sizeof(tcp_header) - inet_hdr_len;
    uint16_t our_mss = htons(conn->tc_our_mss);
    size_t options_len = 0;

    u8 *mss_opt = (u8 *) pbf_push_header(pbf, 4);
    mss_opt[0] = TCP_OPTION_MSS;
    mss_opt[1] = 4;
    memcpy(&mss_opt[2], &our_mss, 2);
    options_len += 4;

    if (conn->tc_opts.has_window_scale)
    {
        u8 *scale_opt = (u8 *) pbf_push_header(pbf, 3);
        scale_opt[0] = TCP_OPTION_WINDOW_SCALE;
        scale_opt[1] = 3;
        scale_opt[2] = 8;
        options_len += 3;
    }

    if (conn->tc_opts.sacking)
    {
        u8 *sack_opt = (u8 *) pbf_push_header(pbf, 2);
        sack_opt[0] = TCP_OPTION_SACK_PERMITTED;
        sack_opt[1] = 2;
        options_len += 2;
    }

    if (options_len % 4)
    {
        unsigned int nops = ALIGN_TO(options_len, 4) - options_len;
        u8 *n = (u8 *) pbf_push_header(pbf, nops);
        memset(n, TCP_OPTION_NOP, nops);
        options_len += nops;
    }

    return options_len;
}

int tcp_send_synack(struct tcp_connreq *conn)
{
    int err;
    struct inet_route *route = &conn->tc_route;
    struct tcp_header *hdr;
    size_t header_len = sizeof(struct tcp_header);
    auto ex = ip::v6::get_v6_proto()->route(conn->tc_src, conn->tc_dst, conn->tc_domain);
    if (ex.has_error())
        return ex.error();
    conn->tc_route = ex.value();

    struct packetbuf *pbf = pbf_alloc(GFP_ATOMIC);
    if (!pbf)
        return -ENOMEM;
    if (!pbf_allocate_space(pbf, MAX_TCP_HEADER_LENGTH))
    {
        pbf_free(pbf);
        return -ENOMEM;
    }

    pbf_reserve_headers(pbf, MAX_TCP_HEADER_LENGTH);

    header_len += tcp_push_synack_options(conn, pbf);
    hdr = (struct tcp_header *) pbf_push_header(pbf, sizeof(struct tcp_header));
    memset(hdr, 0, sizeof(struct tcp_header));

    hdr->ack_number = htonl(conn->tc_rcv_nxt);
    hdr->sequence_number = htonl(conn->tc_iss);
    hdr->dest_port = conn->tc_dst.port;
    hdr->source_port = conn->tc_src.port;
    hdr->window_size = htons(UINT16_MAX);
    hdr->data_offset_and_flags =
        htons(TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(header_len)) |
              (TCP_FLAG_SYN | TCP_FLAG_ACK));

    hdr->checksum = conn->tc_domain == AF_INET
                        ? tcpv4_calculate_checksum(hdr, header_len, pbf, route->dst_addr.in4.s_addr,
                                                   route->src_addr.in4.s_addr, true)
                        : tcpv6_calculate_checksum(hdr, header_len, pbf, route->dst_addr.in6,
                                                   route->src_addr.in6, true);
    iflow flow{*route, IPPROTO_TCP, conn->tc_domain == AF_INET6};
    if (conn->tc_domain == AF_INET)
        err = ip::v4::send_packet(flow, pbf);
    else
        err = ip::v6::send_packet(flow, pbf);
    pbf_put_ref(pbf);
    return err;
}

void __tcp_send_rst(struct packetbuf *pbf, u32 seq, u32 ack_nr, int ack)
{
    struct tcp_header *hdr, *otherhdr;
    struct inet_sock_address from;
    struct inet_sock_address to;
    struct inet_route *other_route = &pbf->route;
    if (pbf->domain == AF_INET)
    {
        from = inet_sock_address{in_addr{other_route->dst_addr.in4}, 0};
        to = inet_sock_address{in_addr{other_route->src_addr.in4}, 0};
    }
    else
    {
        from = inet_sock_address{other_route->dst_addr.in6, 0, pbf->route.nif->if_id};
        to = inet_sock_address{other_route->src_addr.in6, 0, pbf->route.nif->if_id};
    }

    auto ex = ip::v6::get_v6_proto()->route(from, to, pbf->domain);
    if (ex.has_error())
    {
        if (pbf->domain == AF_INET)
        {
            pr_warn("tcp: Failed to route from %pI4 to %pI4 in __tcp_send_rst: %d (how did the "
                    "packet get here?)\n",
                    &from.in4, &to.in4, ex.error());
        }

        return;
    }

    struct packetbuf *rst_pbf = pbf_alloc(GFP_ATOMIC);
    if (!rst_pbf)
        return;
    if (!pbf_allocate_space(rst_pbf, MAX_TCP_HEADER_LENGTH))
    {
        pbf_free(rst_pbf);
        return;
    }

    pbf_reserve_headers(rst_pbf, MAX_TCP_HEADER_LENGTH);

    otherhdr = (struct tcp_header *) pbf->transport_header;
    hdr = (struct tcp_header *) pbf_push_header(rst_pbf, sizeof(struct tcp_header));
    hdr->sequence_number = seq;
    hdr->ack_number = ack_nr;
    hdr->data_offset_and_flags = 0;
    hdr->doff = tcp_header_length_to_data_off(sizeof(struct tcp_header));
    hdr->rst = 1;
    hdr->ack = ack;
    hdr->dest_port = otherhdr->source_port;
    hdr->source_port = otherhdr->dest_port;
    hdr->window_size = 0;
    hdr->urgent_pointer = 0;
    hdr->checksum = 0;

    hdr->checksum =
        pbf->domain == AF_INET
            ? tcpv4_calculate_checksum(hdr, sizeof(struct tcp_header), rst_pbf,
                                       other_route->dst_addr.in4.s_addr,
                                       other_route->src_addr.in4.s_addr, true)
            : tcpv6_calculate_checksum(hdr, sizeof(struct tcp_header), rst_pbf,
                                       other_route->dst_addr.in6, other_route->src_addr.in6, true);
    iflow flow{ex.value(), IPPROTO_TCP, pbf->domain == AF_INET6};
    if (pbf->domain == AF_INET)
        ip::v4::send_packet(flow, rst_pbf);
    else
        ip::v6::send_packet(flow, rst_pbf);
    pbf_put_ref(rst_pbf);
}

void tcp_send_rst(struct tcp_socket *sock, struct packetbuf *pbf)
{
}

const char *state_names[] = {
    "LISTEN",     "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2",
    "CLOSE_WAIT", "CLOSING",  "LAST_ACK",     "TIME_WAIT",   "CLOSED",
};

void tcp_set_state(struct tcp_socket *sock, enum tcp_state state)
{
    pr_info("socket %s -> %s, caller %pS\n", state_names[sock->state], state_names[state],
            __builtin_return_address(0));
    sock->state = state;
    /* Notify poll of a state change */
    wait_queue_wake_all(&sock->rx_wq);
}

#define TCP_MSL 120

static void tcp_do_time_wait_close(struct clockevent *ce)
{
    struct tcp_socket *sock = (struct tcp_socket *) ce->priv;
    sock->ref();
    sock->socket_lock.lock_bh();
    tcp_done(sock);
    sock->socket_lock.unlock_bh();
    sock->unref();
}

void tcp_time_wait(struct tcp_socket *sock)
{
    tcp_set_state(sock, TCP_STATE_TIME_WAIT);
    CHECK(list_is_empty(&sock->output_queue));
    /* We can't actually do this CHECK because the FIN packet is still in on_wire_queue */
    // CHECK(list_is_empty(&sock->on_wire_queue));
    tcp_stop_retransmit(sock);
    sock->retransmit_timer.callback = tcp_do_time_wait_close;
    sock->retransmit_timer.flags = 0;
    sock->retransmit_timer.deadline = clocksource_get_time() + TCP_MSL * NS_PER_SEC;
    sock->retransmit_timer.priv = sock;
    timer_queue_clockevent(&sock->retransmit_timer);
}

static void tcp_set_nodelay(struct tcp_socket *sock, int val)
{
    if (val)
    {
        sock->nagle_enabled = false;
        /* Attempt to output whatever is buffered */
        tcp_output(sock);
    }
    else
        sock->nagle_enabled = true;
}

static int tcp_getsockopt(struct socket *sock_, int level, int optname, void *optval,
                          socklen_t *optlen)
{
    int err;
    struct tcp_socket *sock = TCP_SOCK(sock_);
    if (sock->is_inet_level(level))
        return sock->getsockopt_inet(level, optname, optval, optlen);
    if (level == SOL_SOCKET)
        return sock->getsockopt_socket_level(optname, optval, optlen);

    err = -ENOPROTOOPT;
    sock->socket_lock.lock();
    if (level == SOL_TCP)
    {
        switch (optname)
        {
            case TCP_NODELAY: {
                err =
                    socket::put_option(socket::truthy_to_int(!sock->nagle_enabled), optval, optlen);
                break;
            }
        }
    }

    sock->socket_lock.unlock_sock(sock);
    return err;
}

static int tcp_setsockopt(struct socket *sock_, int level, int optname, const void *optval,
                          socklen_t optlen)
{
    int st, val;
    struct tcp_socket *sock = TCP_SOCK(sock_);
    if (sock->is_inet_level(level))
        return sock->setsockopt_inet(level, optname, optval, optlen);
    if (level == SOL_SOCKET)
        return sock->setsockopt_socket_level(optname, optval, optlen);

    if (level != SOL_TCP)
        return -ENOPROTOOPT;

    auto res = sock->get_socket_option<int>(optval, optlen);
    if (res.has_error())
        return res.error();
    val = res.value();
    st = 0;

    sock->socket_lock.lock();
    switch (optname)
    {
        case TCP_NODELAY: {
            tcp_set_nodelay(sock, val);
            break;
        }

        default:
            st = -ENOPROTOOPT;
    }

    sock->socket_lock.unlock_sock(sock);
    return st;
}
