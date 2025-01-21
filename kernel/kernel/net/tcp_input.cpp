/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdint.h>

#include <onyx/mm/slab.h>
#include <onyx/net/tcp.h>
#include <onyx/random.h>
#include <onyx/rculist.h>
#include <onyx/rcupdate.h>

static void tcp_reset(struct tcp_socket *sock);

struct list_head connreq_table[64];
static struct spinlock connreq_locks[64];

__init static void connreq_tab_init()
{
    for (int i = 0; i < 64; i++)
        INIT_LIST_HEAD(&connreq_table[i]);
}

static void tcp_add_to_synacks(struct tcp_connreq *conn)
{
    const socket_id id(IPPROTO_TCP, AF_INET, conn->tc_src, conn->tc_dst);
    u32 hash = inet_socket::make_hash_from_id(id);
    u32 idx = hash & (64 - 1);

    spin_lock(&connreq_locks[idx]);
    list_add_tail_rcu(&conn->tc_hashtab_node, &connreq_table[idx]);
    spin_unlock(&connreq_locks[idx]);
}

static void tcp_remove_synack(struct tcp_connreq *conn)
{
    const socket_id id(IPPROTO_TCP, AF_INET, conn->tc_src, conn->tc_dst);
    u32 hash = inet_socket::make_hash_from_id(id);
    u32 idx = hash & (64 - 1);

    spin_lock(&connreq_locks[idx]);
    list_remove_rcu(&conn->tc_hashtab_node);
    spin_unlock(&connreq_locks[idx]);
}

static struct tcp_connreq *tcp4_find_synacks(in_addr_t src_ip, in_port_t src_port, in_addr_t dst_ip,
                                             in_port_t dst_port)
{
    struct tcp_connreq *req = NULL;
    const in_addr in = {src_ip};
    const in_addr out = {dst_ip};
    inet_sock_address remote{in, src_port};
    inet_sock_address us{out, dst_port};
    const socket_id id(IPPROTO_TCP, AF_INET, us, remote);

    u32 hash = inet_socket::make_hash_from_id(id);
    u32 idx = hash & (64 - 1);

    rcu_read_lock();

    list_for_each_entry_rcu (req, &connreq_table[idx], tc_hashtab_node)
    {
        if (req->tc_domain != AF_INET)
            continue;
        if (!req->tc_dst.equals(remote, true) || !req->tc_src.equals(us, true))
            continue;
        spin_lock(&req->tc_lock);

        if (req->tc_dead)
        {
            spin_unlock(&req->tc_lock);
            continue;
        }

        goto out;
    }

    req = NULL;
out:
    rcu_read_unlock();
    return req;
}

static void tcp_eat_head(struct packetbuf *pbf, unsigned int len)
{
    /* TODO: Support packetbufs larger than PAGE_SIZE */
    if (len > 0 && pbf->tpi.syn)
    {
        pbf->tpi.syn = 0;
        pbf->tpi.seq_len--;
        len--;
    }

    /* Note: FINs count as the last sequence of a segment, so we don't need to partial eat that. */
    pbf->data += len;
    pbf->tpi.seq += len;
    pbf->tpi.seq_len -= len;
    CHECK(pbf->tpi.seq_len > 0);
}

static int tcp_ack(struct tcp_socket *sock, struct packetbuf *pbuf, struct tcp_header *tcphdr)
{
    u32 ack = tcphdr->ack_number;
    u32 seq = pbuf->tpi.seq;
    u32 old_win;

    /* If the segment acks something not yet sent, send an ACK */
    if (after(ack, sock->snd_next))
    {
        tcp_send_ack(sock);
        return TCP_DROP_ACK_UNSENT;
    }

    /* If SND.UNA =< SEG.ACK =< SND.NXT, the send window should be updated. */
    if (!after(sock->snd_una, ack))
    {
        /* If (SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =< SEG.ACK)), set SND.WND <-
         * SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <- SEG.ACK. -- RFC9293 */
        if (before(sock->snd_wl1, seq) || (sock->snd_wl1 == seq && !after(sock->snd_wl2, ack)))
        {
            sock->snd_wl1 = seq;
            sock->snd_wl2 = ack;
            old_win = sock->snd_wnd;
            sock->snd_wnd = (u32) ntohs(tcphdr->window_size) << sock->snd_wnd_shift;
            /* Attempt to transmit if the new window may allow for it */
            if (old_win < sock->snd_wnd && !list_is_empty(&sock->output_queue))
                tcp_output(sock);
        }
    }

    /* If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK */
    if (!after(ack, sock->snd_una))
        return TCP_DROP_ACK_DUP;

    struct packetbuf *pbf, *next;
    list_for_each_entry_safe (pbf, next, &sock->on_wire_queue, list_node)
    {
        if (!before(pbf->tpi.seq, ack))
            break;

        if (pbf->tpi.fin)
        {
            /* We just got a FIN acked, move states */
            switch (sock->state)
            {
                case TCP_STATE_CLOSING:
                    tcp_time_wait(sock);
                    break;
                case TCP_STATE_FIN_WAIT_1:
                    tcp_set_state(sock, TCP_STATE_FIN_WAIT_2);
                    break;
                case TCP_STATE_LAST_ACK:
                    tcp_set_state(sock, TCP_STATE_CLOSED);
                    break;
                default:
                    pr_warn("tcp: Received ACK to FIN on state %d?\n", sock->state);
                    break;
            }
        }

        if (after(pbf->tpi.seq + pbf->tpi.seq_len, ack))
            tcp_eat_head(pbf, pbf->tpi.seq + pbf->tpi.seq_len - ack);
        else
        {
            list_remove(&pbf->list_node);
            pbf_put_ref(pbf);
        }
    }

    sock->snd_una = ack;

    if (list_is_empty(&sock->on_wire_queue))
        tcp_stop_retransmit(sock);

    return 0;
}

static int tcp_parse_synack_options(struct tcp_synack_options *opts, struct packetbuf *pbf,
                                    struct tcp_header *hdr)
{
    u8 opt_len;
    u16 options_len = tcp_header_data_off_to_length(hdr->doff) - sizeof(struct tcp_header);

    if (!options_len)
        return 0;
    if (pbf_length(pbf) < options_len)
        return TCP_DROP_BAD_PACKET;

    while (options_len)
    {
        u8 *data = NULL;
        u16 *data16;
        u8 *opt = (u8 *) pbf_pull(pbf, 1);
        if (!opt)
            return TCP_DROP_BAD_PACKET;

        if (*opt == TCP_OPTION_END_OF_OPTIONS)
            break;
        if (*opt == TCP_OPTION_NOP)
        {
            options_len--;
            continue;
        }

        options_len -= 2;
        /* For the len */
        if (!pbf_pull(pbf, 1))
            return TCP_DROP_BAD_PACKET;
        opt_len = opt[1] - 2;
        if (opt_len)
        {
            data = (u8 *) pbf_pull(pbf, opt_len);
            if (!data)
                return TCP_DROP_BAD_PACKET;
            options_len -= opt_len;
        }

        switch (*opt)
        {
            case TCP_OPTION_WINDOW_SCALE:
                opts->snd_wnd_shift = data[0];
                if (opts->snd_wnd_shift > 14)
                {
                    /* ratelimited instead? */
                    pr_warn_once("tcp: TCP connection tried to use window shift > 14 (%u), "
                                 "truncating...\n",
                                 opts->snd_wnd_shift);
                    opts->snd_wnd_shift = 14;
                }

                opts->has_window_scale = 1;
                break;
            case TCP_OPTION_SACK_PERMITTED:
                opts->sacking = 1;
                break;
            case TCP_OPTION_MSS:
                data16 = (u16 *) data;
                opts->has_mss = 1;
                opts->mss = ntohs(*data16);
                break;
        }
    }

    return 0;
}

static int tcp_input_syn_sent(struct tcp_socket *sock, struct packetbuf *pbf)
{
    int err;
    struct tcp_header *hdr = (struct tcp_header *) pbf->transport_header;

    if (hdr->ack)
    {
        /* If the ACK bit is set,
           If SEG.ACK =< ISS or SEG.ACK > SND.NXT, send a reset (unless the RST bit is set, if so
           drop the segment and return) - RFC9293
           */
        if (!after(hdr->ack_number, sock->snd_una) || before(hdr->ack_number, sock->snd_next))
        {
            if (!hdr->rst)
                __tcp_send_rst(pbf, hdr->ack_number, 0, 0);
            return TCP_DROP_SYN_BAD_ACK;
        }

        if (hdr->rst)
            goto reset;
        /* Fifth, if neither of the SYN or RST bits is set, then drop the segment and return. -
         * RFC9293 */
        if (!hdr->syn && !hdr->rst)
            return TCP_DROP_NO_SYN;

        struct tcp_synack_options opts = {};
        err = tcp_parse_synack_options(&opts, pbf, hdr);
        if (err)
            return err;

        sock->sacking = opts.sacking;
        if (opts.has_window_scale)
            sock->snd_wnd_shift = opts.snd_wnd_shift;
        if (opts.has_mss)
            sock->rcv_mss = opts.mss;

        sock->mss = min(sock->send_mss, sock->rcv_mss);
        if (!opts.has_window_scale)
        {
            /* Remote host does not support window scaling, use the traditional defaults. */
            sock->rcv_wnd_shift = 0;
            sock->rcv_wnd = UINT16_MAX;
        }

        /* ACK is cromulent, and this is a SYN-ACK. Good. */
        sock->rcv_next = hdr->sequence_number + 1;
        tcp_ack(sock, pbf, hdr);
        /* Window size on SYN and SYN ACK segments is never scaled. */
        sock->snd_wnd = ntohs(hdr->window_size);
        sock->snd_wl1 = hdr->sequence_number;
        sock->snd_wl2 = hdr->ack_number;
        tcp_send_ack(sock);
        tcp_set_state(sock, TCP_STATE_ESTABLISHED);

        sock->mss_for_ack = sock->mss * 10;
        wait_queue_wake_all(&sock->rx_wq);
        return 0;
    }

reset:
    if (hdr->rst)
    {
        tcp_reset(sock);
        return 0;
    }

    if (!hdr->syn)
        return TCP_DROP_NO_SYN;

    /* TODO: Handle SYN but no ACK */
    return 0;
}

static void tcp_ack_timeout(struct clockevent *ev)
{
    struct tcp_socket *sock = (struct tcp_socket *) ev->priv;
    sock->socket_lock.lock_bh();
    if (!sock->socket_lock.is_ours())
    {
        sock->delack_pending = 1;
        sock->proto_needs_work = true;
    }
    else
        tcp_send_ack(sock);

    sock->delack_active = 0;
    sock->socket_lock.unlock_bh();
}

static void tcp_sched_ack(struct tcp_socket *sock)
{
    sock->delack_pending = 1;
    sock->proto_needs_work = true;
}

static void tcp_send_ack_data(struct tcp_socket *sock, struct packetbuf *pbf)
{
    /*
    if (sock->delack_active)
        return;
    sock->delack_timer.callback = tcp_ack_timeout;
    sock->delack_timer.flags = 0;
    sock->delack_timer.deadline = clocksource_get_time() + 100 * NS_PER_MS;
    sock->delack_timer.priv = sock;
    timer_queue_clockevent(&sock->delack_timer);
    */

    sock->mss_for_ack -= pbf_length(pbf);
    if (sock->mss_for_ack <= 0)
    {
        sock->delack_pending = 0;
        sock->mss_for_ack = sock->mss * 10;
        tcp_send_ack(sock);
        return;
    }

    tcp_sched_ack(sock);
}

static inline bool seqs_overlap(u32 seq0, u32 seq0_end, u32 seq1, u32 seq1_end)
{
    return !after(seq0, seq1_end) && !after(seq1, seq0_end);
}

static void tcp_add_sack(struct tcp_socket *sock, u32 start, u32 end)
{
    struct tcp_sack_range *s;
    if (sock->nr_sacks)
    {
        s = &sock->sacks[sock->nr_sacks - 1];
        /* Check if we can merge this sack */
        if (seqs_overlap(start, end, s->start, s->end) || s->end == start || s->start == end)
        {
            /* Merge! */
            s->start = before(s->start, start) ? s->start : start;
            s->end = after(s->end, end) ? s->end : end;
            sock->sack_needs_send = 1;
            sock->proto_needs_work = true;
            return;
        }
    }

    if (sock->nr_sacks == 4)
    {
        if (sock->sack_needs_send)
            tcp_send_ack(sock);

        memmove(&sock->sacks, &sock->sacks[1], 3 * sizeof(struct tcp_sack_range));
        sock->nr_sacks--;
    }

    sock->sacks[sock->nr_sacks++] = {start, end};
    sock->sack_needs_send = 1;
    sock->proto_needs_work = true;
}

static void tcp_remove_sacks(struct tcp_socket *sock)
{
    if (bst_root_empty(&sock->out_of_order_tree))
    {
        sock->nr_sacks = 0;
        return;
    }

    for (unsigned int i = 0; i < sock->nr_sacks; i++)
    {
        if (!before(sock->rcv_next, sock->sacks[i].end))
        {
            /* Fully acked, move everything back */
            for (unsigned int j = i + 1; j < sock->nr_sacks; j++)
                sock->sacks[j - 1] = sock->sacks[j];
            sock->nr_sacks--;
        }
    }
}

static int tcp_do_out_of_order(struct tcp_socket *sock, struct packetbuf *pbf)
{
    struct packetbuf *pbf2;
    struct bst_node **nodep, *parent, *cur;
    u32 end_seq = pbf->tpi.seq + pbf->tpi.seq_len;
    u32 seq = pbf->tpi.seq;
    u32 other_end;
    bst_node_initialize(&pbf->bst_node);
    int res;

    /* Handle out of order segments by organizing them in a binary search tree (maple tree cannot be
     * used as it does not support wraparound). Special care needs to be had when walking the tree,
     * comparing the segments with wraparound protection and being mindful of segments overlapping
     * each other. */

    cur = sock->out_of_order_tree.root;
    nodep = &sock->out_of_order_tree.root;
    parent = NULL;

    while (cur)
    {
        pbf2 = container_of(cur, struct packetbuf, bst_node);
        other_end = pbf2->tpi.seq + pbf2->tpi.seq_len;

        if (before(seq, pbf2->tpi.seq))
        {
            res = -1;
            goto iterate;
        }

        /* <pbf2 start> ... <pbf start> ... <pbf2 end> */
        if (before(seq, other_end))
        {
            /* We're overlapping with this segment. Now check exactly how we're doing it, and deal
             * with it */
            if (!after(end_seq, other_end))
            {
                /* <pbf2 start> ... <pbf start> ... <pbf start> ... <pbf2 end>
                 * Fully contained, drop it as duplicate. */
                return TCP_DROP_OOO_DUP;
            }

            /* We now know end_seq > other_end */
            if (after(seq, pbf2->tpi.seq))
            {
                /* <pbf2 start> ... <seq> <pbf2 end> <end_seq>
                 * Partial overlap on the end there, eat this pbf's head */
                tcp_eat_head(pbf, other_end - seq);
            }
            else
            {
                /* seq == pbf2->seq and end_seq is beyond other_seq... Replace this segment and eat
                 * next nodes, if required */
                bst_replace_node(&sock->out_of_order_tree, &pbf2->bst_node, &pbf->bst_node);
                goto eat_next;
            }
        }

        /* Go right */
        res = 1;
    iterate:
        parent = cur;
        nodep = &cur->child[res > 0];
        cur = *nodep;
    }

    bst_link(nodep, parent, &pbf->bst_node);
    bst_update_rank_insert(&sock->out_of_order_tree, &pbf->bst_node, NULL);
    pbf_get(pbf);
    if (sock->sacking)
        tcp_add_sack(sock, pbf->tpi.seq, pbf->tpi.seq + pbf->tpi.seq_len);
eat_next:
    while ((
        pbf2 = bst_next_type(&sock->out_of_order_tree, &pbf->bst_node, struct packetbuf, bst_node)))
    {
        if (!after(end_seq, pbf2->tpi.seq))
            break;

        if (before(end_seq, pbf2->tpi.seq + pbf2->tpi.seq_len))
        {
            tcp_eat_head(pbf, pbf2->tpi.seq + pbf2->tpi.seq_len - end_seq);
            break;
        }
        else
        {
            bst_delete(&sock->out_of_order_tree, &pbf2->bst_node);
            pbf_put_ref(pbf2);
        }
    }

    return 0;
}

static void tcp_attempt_ooo_queue(struct tcp_socket *sock)
{
    struct packetbuf *pbf;
    bst_for_every_entry(&sock->out_of_order_tree, pbf, struct packetbuf, bst_node)
    {
        if (before(sock->rcv_next, pbf->tpi.seq))
        {
            /* Gap still exists, stop */
            break;
        }

        /* We could have a new segment that overrides this old segment, either partially or fully.
         * Partial overlaps just eat the old's head, else delete and put. */
        if (after(sock->rcv_next, pbf->tpi.seq))
        {
            if (before(sock->rcv_next, pbf->tpi.seq + pbf->tpi.seq_len))
                tcp_eat_head(pbf, sock->rcv_next - pbf->tpi.seq);
            else
            {
                bst_delete(&sock->out_of_order_tree, &pbf->bst_node);
                pbf_put_ref(pbf);
                continue;
            }
        }

        CHECK(pbf->tpi.seq == sock->rcv_next);
        bst_delete(&sock->out_of_order_tree, &pbf->bst_node);
        list_add_tail(&pbf->list_node, &sock->read_queue);
        sock->rcv_next = pbf->tpi.seq + pbf->tpi.seq_len;
    }
}

static int tcp_queue_data(struct tcp_socket *sock, struct packetbuf *pbf)
{
    int err = 0;
    if (unlikely(sock->rcv_next != pbf->tpi.seq))
    {
        /* Schedule a duplicate ack since we're missing a packet. tcp_do_out_of_order will take care
         * of any sacking. */
        tcp_sched_ack(sock);
        err = tcp_do_out_of_order(sock, pbf);
        if (err)
            return err;
        return 0;
    }

    list_add_tail(&pbf->list_node, &sock->read_queue);
    pbf_get(pbf);
    sock->rcv_next = pbf->tpi.seq + pbf->tpi.seq_len;

    if (unlikely(!bst_root_empty(&sock->out_of_order_tree)))
    {
        tcp_attempt_ooo_queue(sock);
        tcp_remove_sacks(sock);
    }

    wait_queue_wake_all(&sock->rx_wq);
    tcp_send_ack_data(sock, pbf);
    return 0;
}

/* Check segment sequence number for validity.
 *
 * Segment controls are considered valid, if the segment
 * fits to the window after truncation to the window. Acceptability
 * of data (and SYN, FIN, of course) is checked separately.
 * See tcp_data_queue(), for example.
 *
 * Also, controls (RST is main one) are accepted using RCV.WUP instead
 * of RCV.NXT. Peer still did not advance his SND.UNA when we
 * delayed ACK, so that hisSND.UNA<=ourRCV.WUP.
 * (borrowed from freebsd)
 */

static int tcp_sequence(const struct tcp_socket *sock, u32 seq, u32 end_seq)
{
    if (before(end_seq, sock->rcv_next))
        return TCP_DROP_UNCROMULENT1;

    if (after(seq, sock->rcv_next + sock->rcv_wnd))
        return TCP_DROP_UNCROMULENT2;

    return 0;
}

static int tcp_handle_fin(struct tcp_socket *sock, struct packetbuf *pbf, struct tcp_header *hdr)
{
    /* If the FIN bit is set, signal the user "connection closing" and return any pending
     * RECEIVEs with same message, advance RCV.NXT over the FIN, and send an acknowledgment for
     * the FIN. Note that FIN implies PUSH for any segment text not yet delivered to the user. -
     * RFC9293 */

    if (pbf->tpi.seq_len == 1)
    {
        /* Segment with data was already acked and rcv_next adjusted, no need to do this again.
         */
        sock->rcv_next = pbf->tpi.seq + pbf->tpi.seq_len;
        tcp_send_ack(sock);
    }

    sock->shutdown_state |= SHUTDOWN_RD;

    /* rcv_next advanced and acked, handle state transitions (these are all defined
     * per RFC) and ack it . */
    switch (sock->state)
    {
        case TCP_STATE_LAST_ACK:
            /* Note: LAST_ACK -> CLOSED means you can just destroy the socket, no problem. */
            tcp_set_state(sock, TCP_STATE_CLOSED);
            break;
        case TCP_STATE_SYN_RECEIVED:
        case TCP_STATE_ESTABLISHED:
            /* Move into CLOSE_WAIT (waiting for the client to CLOSE) */
            tcp_set_state(sock, TCP_STATE_CLOSE_WAIT);
            break;
        case TCP_STATE_FIN_WAIT_1:
            /* Simultaneous close - go to CLOSING and ack it */
            tcp_set_state(sock, TCP_STATE_CLOSING);
            break;
        case TCP_STATE_FIN_WAIT_2:
            tcp_time_wait(sock);
            break;
        default:
            pr_warn("tcp: FIN with state %u\n", sock->state);
            break;
    }

    return 0;
}

static void tcp_reset(struct tcp_socket *sock)
{
    int err;
    switch (sock->state)
    {
        case TCP_STATE_SYN_SENT:
            err = ECONNREFUSED;
            break;
        case TCP_STATE_CLOSE_WAIT:
            err = EPIPE;
            break;
        default:
            err = ECONNRESET;
            break;
    }

    tcp_done_error(sock, err);
}

static inline void tcp_connreq_init(struct tcp_socket *sock, struct tcp_connreq *conn,
                                    struct packetbuf *pbf)
{
    struct tcp_header *hdr = (struct tcp_header *) pbf->transport_header;
    struct inet_route *route = &pbf->route;
    memset((void *) conn, 0, sizeof(*conn));
    spinlock_init(&conn->tc_lock);

    conn->tc_sock = sock;
    conn->tc_domain = pbf->domain;

    inet_sock_address from;
    inet_sock_address to;
    if (conn->tc_domain == AF_INET)
    {
        auto iphdr = (ip_header *) pbf->net_header;
        from = inet_sock_address{in_addr{iphdr->dest_ip}, hdr->dest_port};
        to = inet_sock_address{in_addr{iphdr->source_ip}, hdr->source_port};
    }
    else
    {
        auto iphdr = (ip6hdr *) pbf->net_header;
        from = inet_sock_address{iphdr->dst_addr, hdr->dest_port, route->nif->if_id};
        to = inet_sock_address{iphdr->src_addr, hdr->source_port, route->nif->if_id};
    }

    conn->tc_src = from;
    conn->tc_dst = to;
    conn->tc_iss = arc4random();
    conn->tc_rcv_nxt = hdr->sequence_number + 1;
}

static int tcp_input_listen(struct tcp_socket *sock, struct packetbuf *pbf)
{
    int err;
    struct tcp_connreq *connreq;
    struct tcp_header *hdr = (struct tcp_header *) pbf->transport_header;

    /* 1) An incoming RST should be ignored. Return */
    if (hdr->rst)
        return TCP_DROP_RST_ON_LISTEN;

    /* Any acknowledgment is bad if it arrives on a connection still in the LISTEN state. An
     * acceptable reset segment should be formed for any arriving ACK-bearing segment -- RFC9293
     */
    if (hdr->ack)
    {
        __tcp_send_rst(pbf, hdr->ack_number, 0, 0);
        return 0;
    }

    /* Fourth, other data or control: This should not be reached. Drop the segment and return. */
    if (!hdr->syn)
        return TCP_DROP_BAD_PACKET;

    /* This is a SYN. Parse it out and create a tcp_connreq for this */
    connreq = (struct tcp_connreq *) kmalloc(sizeof(*connreq), GFP_ATOMIC);
    if (!connreq)
        return -ENOMEM;
    tcp_connreq_init(sock, connreq, pbf);

    err = tcp_parse_synack_options(&connreq->tc_opts, pbf, hdr);
    if (err)
    {
        kfree(connreq);
        return -ENOMEM;
    }

    list_add_tail(&connreq->tc_list_node, &sock->conn_queue);

    if (pbf_length(pbf) > 0)
    {
        /* This SYN has data. Keep it. */
        connreq->tc_syndata = pbf;
        pbf_get(pbf);
    }

    tcp_add_to_synacks(connreq);

    err = tcp_send_synack(connreq);
    if (err)
    {
        kfree(connreq);
        return err;
    }

    return 0;
}

static int tcp_input_conn(struct tcp_connreq *conn, struct packetbuf *pbf)
{
    struct tcp_socket *sock, *parent;
    struct tcp_header *hdr = (struct tcp_header *) pbf->transport_header;
    CHECK(spin_lock_held(&conn->tc_lock));
    /* Make this connreq into a real socket */

    sock = (struct tcp_socket *) tcp_create_socket(SOCK_STREAM);
    if (!sock)
        return -ENOMEM;

    sock->rcv_mss = conn->tc_domain == AF_INET ? 536 : 1220;
    sock->send_mss = conn->tc_our_mss;
    sock->rcv_next = conn->tc_rcv_nxt;
    sock->snd_una = conn->tc_iss;
    sock->snd_next = sock->snd_una + 1;
    if (conn->tc_opts.has_mss)
        sock->rcv_mss = conn->tc_opts.mss;
    if (conn->tc_opts.has_window_scale)
    {
        sock->snd_wnd = (u32) ntohs(hdr->window_size) << conn->tc_opts.snd_wnd_shift;
        sock->snd_wnd_shift = conn->tc_opts.snd_wnd_shift;
        sock->rcv_wnd = 0xffff * 128;
        sock->rcv_wnd_shift = conn->tc_opts.snd_wnd_shift;
    }
    else
    {
        /* Remote host does not support window scaling, use the traditional defaults. */
        sock->snd_wnd = ntohs(hdr->window_size);
        sock->snd_wnd_shift = 0;
        sock->rcv_wnd_shift = 0;
        sock->rcv_wnd = UINT16_MAX;
    }

    if (conn->tc_opts.sacking)
        sock->sacking = 1;

    bool on_ipv4_mode = conn->tc_domain == AF_INET && conn->tc_sock->domain == AF_INET6;

    sock->dest_addr = conn->tc_dst;
    sock->src_addr = conn->tc_src;
    sock->ipv4_on_inet6 = on_ipv4_mode;
    sock->route_cache = cul::move(conn->tc_route);
    sock->route_cache_valid = 1;
    sock->proto_domain =
        conn->tc_sock->domain == AF_INET ? ip::v4::get_v4_proto() : ip::v6::get_v6_proto();
    sock->domain = conn->tc_sock->domain;
    sock->proto = conn->tc_sock->proto;
    sock->type = conn->tc_sock->type;

    /* Note: We bind while holding tc_lock, so no segments may get lost. Others may observe the
     * !dead connreq in the lists, or a bound socket, but never neither. */
    if (WARN_ON(!inet_proto_family::add_socket(sock)))
    {
        /* This should not be possible... */
        kfree(sock);
        return -EINVAL;
    }

    sock->mss = min(sock->send_mss, sock->rcv_mss);

    /* We'll put our state as SYN_RECEIVED. The generic receive code will take care of moving our
     * state forwards. */
    /* TODO: https://datatracker.ietf.org/doc/html/rfc9293#section-3.10.7.4-2.5.2.2.2.2.2.2.1 */
    tcp_set_state(sock, TCP_STATE_SYN_RECEIVED);
    sock->connected = true;
    sock->bound = true;

    /* Now that we're releasing the lock, we need to tell new segments to go for the proper bound
     * socket instead. */
    conn->tc_dead = 1;
    parent = conn->tc_sock;
    rcu_read_lock();

    spin_unlock(&conn->tc_lock);

    tcp_remove_synack(conn);

    /* TRICKYNESS ENSUING: No locks are held at the moment. Because the connreq isn't dead
     * (!tc_dead) _and it's locked_, we know the parent socket is valid and alive. So we need to
     * dequeue and requeue ourselves in the parent socket. Because locking ordering goes:
     *  sock->lock -> connreq->tc_lock
     * we need to release our lock and relock from the top. This only works properly because we
     * hold the RCU read lock and the tcp_socket cache is TYPESAFE_BY_RCU. So, basically, in a nice
     * diagram:
     *  [grabbed connreq from queues, locked, !tc_dead, tc_sock valid] -> [tc_dead = 1, grab valid
     * sock pointer] -> [grab rcu read lock, unlock tc_lock (sock pointer type stability is
     * guaranteed)] -> [lock sock, lock tc_lock] -> [recheck tc_sock. If it changed, we got
     * killed by socket destruction].
     **/

    /* Under the RCU lock (reference has to be valid), grab the ref if not zero, then lock, then
     * recheck stuff. The ref makes it so socket_lock doesn't go byebye while we hold it.
     * TODO: Maybe we could avoid this?
     **/
    if (!parent->ref_not_zero())
    {
        spin_unlock(&conn->tc_lock);
        tcp_set_state(sock, TCP_STATE_CLOSED);
        sock->unref();
        return 0;
    }

    parent->socket_lock.lock_bh();
    spin_lock(&conn->tc_lock);

    if (conn->tc_sock != parent)
    {
        /* We were deleted :( Kill the socket and bail. Whoever killed us already sent a RST anyway.
         */
        tcp_set_state(sock, TCP_STATE_CLOSED);
        sock->unref();
    }
    else
    {
        list_remove(&conn->tc_list_node);
        kfree_rcu(conn, tc_rcu_head);
        /* We can double up this conn_queue as a list node, because sock->conn_queue will never be
         * in a LISTEN state */
        list_add_tail(&sock->conn_queue, &parent->conn_queue);
        wait_queue_wake_all(&parent->rx_wq);
    }

    spin_unlock(&conn->tc_lock);
    parent->socket_lock.unlock_bh();

    parent->unref();
    rcu_read_unlock();
    return 0;
}

static int tcp_parse_options(struct tcp_socket *sock, struct packetbuf *pbf)
{
    struct tcp_header *hdr = (struct tcp_header *) pbf->transport_header;
    u16 options_len = tcp_header_data_off_to_length(hdr->doff) - sizeof(struct tcp_header);
    u8 opt_len;

    if (pbf_length(pbf) < options_len)
        return TCP_DROP_BAD_PACKET;

    while (options_len)
    {
        u8 *data;
        u8 *opt = (u8 *) pbf_pull(pbf, 1);
        if (!opt)
            return TCP_DROP_BAD_PACKET;

        if (*opt == TCP_OPTION_END_OF_OPTIONS)
            break;
        if (*opt == TCP_OPTION_NOP)
        {
            options_len--;
            continue;
        }

        options_len -= 2;
        /* For the len */
        if (!pbf_pull(pbf, 1))
            return TCP_DROP_BAD_PACKET;
        opt_len = opt[1] - 2;
        if (!opt_len)
            continue;
        data = (u8 *) pbf_pull(pbf, opt_len);
        if (!data)
            return TCP_DROP_BAD_PACKET;
        options_len -= opt_len;

        switch (*opt)
        {
            case TCP_OPTION_SACK:
                if (!sock->sacking)
                    return TCP_DROP_BAD_PACKET;
                /* TODO: Actually sack */
                break;
            default:
                /* Drop packets with options we don't recognize */
                return TCP_DROP_BAD_PACKET;
        }
    }

    return 0;
}

int tcp_input(struct tcp_socket *sock, struct packetbuf *pbf)
{
    unsigned int seg_len;
    u32 seq;
    int err;
    struct tcp_header *hdr = (struct tcp_header *) pbf->transport_header;
    /* Byte swap fields before being used by the rest of the network stack - this will save us a
     * bunch of byteswaps and annoying code. */
    hdr->ack_number = ntohl(hdr->ack_number);
    hdr->sequence_number = ntohl(hdr->sequence_number);
    seg_len = pbf_length(pbf) - (tcp_header_data_off_to_length(hdr->doff) - sizeof(tcp_header));
    seq = hdr->sequence_number;

    pbf->tpi.seq_len = seg_len + (hdr->syn + hdr->fin);
    pbf->tpi.seq = seq;

// TCP_DEBUG
#ifdef TCP_DEBUG
    int i = 0;
    char flags[6];
    if (hdr->syn)
        flags[i++] = 'S';
    if (hdr->ack)
        flags[i++] = 'A';
    if (hdr->fin)
        flags[i++] = 'F';
    if (hdr->rst)
        flags[i++] = 'R';
    flags[i++] = 0;
    pr_warn("flags %s seq %u seqlen %u rcv next %u rcv wnd %u\n", flags, pbf->tpi.seq,
            pbf->tpi.seq_len, sock->rcv_next, sock->rcv_wnd);
#endif

    if (sock->state == TCP_STATE_LISTEN)
        return tcp_input_listen(sock, pbf);
    if (sock->state == TCP_STATE_SYN_SENT)
        return tcp_input_syn_sent(sock, pbf);
    switch (sock->state)
    {
        default:
            return 0;
        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
        case TCP_STATE_CLOSE_WAIT:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
        case TCP_STATE_ESTABLISHED:
        case TCP_STATE_SYN_RECEIVED:
        case TCP_STATE_TIME_WAIT:;
            /* fallthrough */
    }

    if (hdr->doff > 5)
    {
        err = tcp_parse_options(sock, pbf);
        if (err)
            goto not_acceptable;
    }

    /* There are four cases for the acceptability test for an incoming segment: - RFC9293 */
    err = tcp_sequence(sock, pbf->tpi.seq, pbf->tpi.seq + pbf->tpi.seq_len);
    if (err)
        goto not_acceptable;

    /* Second, check the RST bit: */
    if (unlikely(hdr->rst))
    {
        /* TODO: RFC 5961 */
        tcp_reset(sock);
        return 0;
    }

    if (hdr->syn)
    {
        /* RFC 5961 recommends that in these synchronized states, if the SYN bit is set,
         * irrespective of the sequence number, TCP endpoints MUST send a "challenge ACK" to the
         * remote peer */
        tcp_send_ack(sock);
        return TCP_DROP_BAD_SYN;
    }

    if (!hdr->ack)
        return TCP_DROP_NOACK;

    if (sock->state == TCP_STATE_SYN_RECEIVED)
    {
        /* If SND.UNA < SEG.ACK =< SND.NXT, then enter ESTABLISHED state and continue processing
         */
        if (after(hdr->ack_number, sock->snd_una) && !after(hdr->ack_number, sock->snd_next))
        {
            tcp_set_state(sock, TCP_STATE_ESTABLISHED);
            sock->snd_wnd = (u32) ntohs(hdr->window_size) << sock->snd_wnd_shift;
            sock->snd_wl1 = hdr->sequence_number;
            sock->snd_wl2 = hdr->ack_number;
            pr_warn("established\n");
        }
        /* TODO: If the segment acknowledgment is not acceptable, form a reset segment and send
         * it
         */
    }

    err = tcp_ack(sock, pbf, hdr);
    if (err && err != TCP_DROP_ACK_DUP)
        return err;

    if (seg_len > 0)
        err = tcp_queue_data(sock, pbf);
    if (unlikely(hdr->fin))
        err = tcp_handle_fin(sock, pbf, hdr);
    return err;
not_acceptable:
    if (!hdr->rst)
        tcp_send_ack(sock);
    return err;
}

static int tcp_in_pbf(struct tcp_socket *sock, struct packetbuf *pbf)
{
    int err;

    sock->socket_lock.lock_bh();
    if (!sock->socket_lock.is_ours())
    {
        pbf_get(pbf);
        sock->add_backlog(&pbf->list_node);
        sock->socket_lock.unlock_bh();
        return 0;
    }

    err = tcp_input(sock, pbf);
    if (err)
        pr_info("segment drop %d\n", err);
    sock->socket_lock.unlock_bh();
    return err;
}

bool validate_tcp_packet(const tcp_header *header, size_t size)
{
    auto flags = ntohs(header->data_offset_and_flags);

    uint16_t data_off = flags >> TCP_DATA_OFFSET_SHIFT;
    size_t off_bytes = tcp_header_data_off_to_length(data_off);

    if (off_bytes > size + sizeof(struct tcp_header)) [[unlikely]]
        return false;

    if (off_bytes < sizeof(tcp_header)) [[unlikely]]
        return false;

    return true;
}

static void tcp_rst_closed(struct packetbuf *pbf, struct tcp_header *hdr)
{
    int ack;
    u32 ack_nr, seq;
    if (!hdr->ack)
    {
        /* <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK> */
        u32 len = pbf_length(pbf) -
                  (tcp_header_data_off_to_length(hdr->doff) - sizeof(struct tcp_header)) +
                  hdr->syn + hdr->fin;
        ack = 1;
        ack_nr = htonl(ntohl(hdr->sequence_number) + len);
        seq = 0;
    }
    else
    {
        /* <SEQ=SEG.ACK><CTL=RST> */
        seq = hdr->ack_number;
        ack = 0;
        ack_nr = 0;
    }

    __tcp_send_rst(pbf, seq, ack_nr, ack);
}

int tcp_handle_packet(const inet_route &route, packetbuf *buf)
{
    struct tcp_connreq *conn;
    int err;
    auto ip_header = (struct ip_header *) buf->net_header;
    auto header = (struct tcp_header *) pbf_pull(buf, sizeof(struct tcp_header));

    if (!header || !validate_tcp_packet(header, buf->length())) [[unlikely]]
        return TCP_DROP_BAD_PACKET;

    buf->domain = AF_INET;
    buf->transport_header = (unsigned char *) header;

    // TCP connections don't run on broadcast/mcast
    if (route.flags & (INET4_ROUTE_FLAG_BROADCAST | INET4_ROUTE_FLAG_MULTICAST))
        return TCP_DROP_BAD_PACKET;

    conn = tcp4_find_synacks(ip_header->source_ip, header->source_port, ip_header->dest_ip,
                             header->dest_port);
    if (unlikely(conn))
    {
        err = tcp_input_conn(conn, buf);
        if (err)
            return err;
        /* Fallthrough. Generic code will handle the rest of the connection */
    }

    ref_guard<tcp_socket> socket{inet_resolve_socket_conn<tcp_socket>(
        ip_header->source_ip, header->source_port, header->dest_port, IPPROTO_TCP, route.nif,
        &tcp_proto)};

    if (!socket || socket->state == TCP_STATE_CLOSED)
    {
        /* If the state is CLOSED (i.e., TCB does not exist), then all data in the incoming
         * segment is discarded. An incoming segment containing a RST is discarded. An incoming
         * segment not containing a RST causes a RST to be sent in response --RFC9293 */
        if (!header->rst)
            tcp_rst_closed(buf, header);
        /* No socket bound, bad packet. */
        return TCP_DROP_NOSOCK;
    }

    return tcp_in_pbf(socket.get(), buf);
}

int tcp6_handle_packet(const inet_route &route, packetbuf *buf)
{
    auto ip_header = (struct ip6hdr *) buf->net_header;
    auto header = (struct tcp_header *) pbf_pull(buf, sizeof(struct tcp_header));

    if (!header || !validate_tcp_packet(header, buf->length())) [[unlikely]]
        return TCP_DROP_BAD_PACKET;

    buf->domain = AF_INET6;
    buf->transport_header = (unsigned char *) header;

    // TCP connections don't run on broadcast/mcast
    if (route.flags & (INET4_ROUTE_FLAG_BROADCAST | INET4_ROUTE_FLAG_MULTICAST))
        return TCP_DROP_BAD_PACKET;

    ref_guard<tcp_socket> socket{inet6_resolve_socket_conn<tcp_socket>(
        ip_header->src_addr, header->source_port, ip_header->dst_addr, header->dest_port,
        IPPROTO_TCP, route.nif, &tcp_proto)};

    if (!socket || socket->state == TCP_STATE_CLOSED)
    {
        /* If the state is CLOSED (i.e., TCB does not exist), then all data in the incoming
         * segment is discarded. An incoming segment containing a RST is discarded. An incoming
         * segment not containing a RST causes a RST to be sent in response --RFC9293 */
        if (!header->rst)
            tcp_rst_closed(buf, header);
        /* No socket bound, bad packet. */
        return TCP_DROP_NOSOCK;
    }

    return tcp_in_pbf(socket.get(), buf);
}
