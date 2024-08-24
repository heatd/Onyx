/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>

#include <onyx/byteswap.h>
#include <onyx/net/inet_proto.h>
#include <onyx/net/ip.h>
#include <onyx/net/socket_table.h>
#include <onyx/net/tcp.h>
#include <onyx/poll.h>
#include <onyx/random.h>
#include <onyx/timer.h>

socket_table tcp_table;

const inet_proto tcp_proto{"tcp", &tcp_table};

uint16_t tcpv4_calculate_checksum(const tcp_header *header, uint16_t packet_length, uint32_t srcip,
                                  uint32_t dstip, bool calc_data = true);
uint16_t tcpv6_calculate_checksum(const tcp_header *header, uint16_t packet_length,
                                  const in6_addr &srcip, const in6_addr &dstip, bool calc_data);

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
uint16_t tcp_calculate_checksum(const tcp_header *header, uint16_t len, const inet_route::addr &src,
                                const inet_route::addr &dest, bool do_rest_of_packet = true)
{
    uint16_t result = 0;
    if constexpr (domain == AF_INET6)
    {
        result = tcpv6_calculate_checksum(header, len, src.in6, dest.in6, do_rest_of_packet);
    }
    else
    {
        result = tcpv4_calculate_checksum(header, len, src.in4.s_addr, dest.in4.s_addr,
                                          do_rest_of_packet);
    }

    // Checksum offloading needs an unfolded checksum
    return do_rest_of_packet ? result : ~result;
}

#define TCP_MAKE_DATA_OFF(off) (off << TCP_DATA_OFFSET_SHIFT)

int tcp_init_netif(struct netif *netif)
{
    return 0;
}

int tcp_socket::bind(struct sockaddr *addr, socklen_t addrlen)
{
    auto fam = get_proto_fam();

    return fam->bind(addr, addrlen, this);
}

bool validate_tcp_packet(const tcp_header *header, size_t size)
{
    if (sizeof(tcp_header) > size) [[unlikely]]
        return false;

    auto flags = ntohs(header->data_offset_and_flags);

    uint16_t data_off = flags >> TCP_DATA_OFFSET_SHIFT;
    size_t off_bytes = tcp_header_data_off_to_length(data_off);

    if (off_bytes > size) [[unlikely]]
        return false;

    if (off_bytes < sizeof(tcp_header)) [[unlikely]]
        return false;

    return true;
}

/**
 * @brief Handle packet recv on SYN_SENT
 *
 * @param data Packet handling data
 * @return 0 on success, negative error codes
 */
int tcp_socket::do_receive_syn_sent(const packet_handling_data &data)
{
    auto tcphdr = data.header;
    const auto flags = htons(tcphdr->data_offset_and_flags);
    constexpr int valid_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    if ((flags & 0xff) != valid_flags)
        return -1;

    if (!parse_options(tcphdr))
    {
        /* Invalid packet */
        state = tcp_state::TCP_STATE_CLOSED;
        return -EIO;
    }

    window_size = ntohs(tcphdr->window_size) << window_size_shift;

    auto starting_seq_number = ntohl(tcphdr->sequence_number);
    uint32_t seqs = 1;
    rcv_next = starting_seq_number + seqs;

    do_ack(data.buffer);

    tcp_packet pkt{{}, this, TCP_FLAG_ACK, src_addr};

    auto res = pkt.result();

    if (!res)
    {
        state = tcp_state::TCP_STATE_CLOSED;
        sock_err = ENOBUFS;
        return -ENOBUFS;
    }

    auto ex = sendpbuf(res.get(), true);

    if (ex.has_error())
    {
        state = tcp_state::TCP_STATE_CLOSED;
        sock_err = -ex.error();
        return ex.error();
    }

    state = tcp_state::TCP_STATE_ESTABLISHED;

    return 0;
}

static void tcp_eat_head(struct packetbuf *pbf, unsigned int len)
{
    /* TODO: Support packetbufs larger than PAGE_SIZE */
    pbf->data += len;
    pbf->tpi.seq += len;
    pbf->tpi.seq_len -= len;
}

/**
 * @brief Do the ACK
 * @param new_una New snd_una
 *
 * @return True if ack completely covers the packet (i.e can be freed)
 */
bool tcp_pending_out::do_ack(u32 new_una)
{
    u32 ack_length = buf->tpi.seq_len;

    u32 final_seq = buf->tpi.seq + ack_length;
    if (final_seq > new_una)
    {
        /* Partial ACK. Eat up the packetbuf's head */
        tcp_eat_head(buf.get(), new_una - buf->tpi.seq);
        return false;
    }

    acked = true;
    if (done_callback)
        done_callback(this);
    return true;
}
/**
 * @brief Does acknowledgement of packets
 *
 * @param buf Packetbuf of the ack packet we got
 */
int tcp_socket::do_ack(packetbuf *buf)
{
    tcp_header *tcphdr = (tcp_header *) buf->transport_header;
    u32 ack = ntohl(tcphdr->ack_number);

    /* If the segment acks something not yet sent, send an ACK */
    if (ack > snd_next)
    {
        send_ack();
        return TCP_DROP_ACK_UNSENT;
    }

    /* If SND.UNA < SEG.ACK =< SND.NXT, then set SND.UNA <- SEG.ACK */
    if (snd_una >= ack)
        return TCP_DROP_ACK_DUP;

    /* TODO: Send window updates (if ack == snd_una) */

    scoped_lock g{pending_out_lock};
    list_for_every_safe (&pending_out_packets)
    {
        auto pkt = list_head_cpp<tcp_pending_out>::self_from_list_head(l);

        if (!pkt->ack_for_packet(snd_una - 1, ack))
            continue;

        auto tph = (tcp_header *) pkt->buf->transport_header;

        if (ntohs(tph->data_offset_and_flags) & TCP_FLAG_FIN)
        {
            // We just got a FIN acked, move states to FIN_WAIT_2
            state = tcp_state::TCP_STATE_FIN_WAIT_2;
        }

        if (pkt->do_ack(ack))
        {
            wait_queue_wake_all(&pkt->wq);
            pkt->remove();
            /* Unref *must* be the last thing we do */
            pkt->unref();
        }
    }

    if (list_is_empty(&pending_out_packets))
        stop_retransmit();

    snd_una = ack;
    g.unlock();

    return 0;
}

/**
 * @brief Send a reset segment
 *
 */
void tcp_socket::send_reset()
{
    auto pbuf = make_refc<packetbuf>();

    if (!pbuf)
        return;

    if (!pbuf->allocate_space(MAX_TCP_HEADER_LENGTH))
        return;

    pbuf->reserve_headers(MAX_TCP_HEADER_LENGTH);
    tcp_header *tph = (tcp_header *) pbuf->push_header(sizeof(tcp_header));

    unsigned int flags = TCP_FLAG_ACK | TCP_FLAG_FIN;

    pbuf->transport_header = (unsigned char *) tph;

    memset(tph, 0, sizeof(tcp_header));

    auto &dest = daddr();

    auto data_off = TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(sizeof(tcp_header)));

    /* Assume the max window size as the window size, for now */
    tph->window_size = htons(our_window_size);
    tph->source_port = saddr().port;
    tph->sequence_number = htonl(snd_next);
    tph->data_offset_and_flags = htons(data_off | flags);
    tph->dest_port = dest.port;
    tph->urgent_pointer = 0;

    tph->ack_number = htonl(acknowledge_nr());

    auto &route = route_cache;
    auto nif = route.nif;

    bool need_csum = true;

    if (can_offload_csum(nif, pbuf.get()))
    {
        pbuf->csum_offset = &tph->checksum;
        pbuf->csum_start = (unsigned char *) tph;
        pbuf->needs_csum = 1;
        need_csum = false;
    }

    tph->checksum =
        call_based_on_inet(tcp_calculate_checksum, tph, static_cast<uint16_t>(sizeof(tcp_header)),
                           route.src_addr, route.dst_addr, need_csum);

    iflow flow{route_cache, IPPROTO_TCP, effective_domain() == AF_INET6};

    if (effective_domain() == AF_INET)
        ip::v4::send_packet(flow, pbuf.get());
    else
        ip::v6::send_packet(flow, pbuf.get());
}
/**
 * @brief Reset the connection
 *
 */
void tcp_socket::reset()
{
    sock_err = ECONNRESET;

    scoped_lock g{pending_out_lock};

    list_for_every_safe (&pending_out_packets)
    {
        auto pkt = list_head_cpp<tcp_pending_out>::self_from_list_head(l);
        pkt->reset = true;
        wait_queue_wake_all(&pkt->wq);
        pkt->remove();

        /* Unref *must* be the last thing we do */
        pkt->unref();
    }

    state = tcp_state::TCP_STATE_CLOSED;
}

// The (maximum segment lifetime) MSL is defined as 120 seconds
#define TCP_MSL 120

void tcp_socket::set_time_wait()
{
    time_wait_timer = make_unique<clockevent>();
    if (!time_wait_timer)
    {
        // Uhh, what?
        // Maybe find a way to destroy ourselves here?
        return;
    }

    // RFC793 says to remain in TIME_WAIT state for 2MSL seconds
    time_wait_timer->deadline = clocksource_get_time() + 2 * TCP_MSL * NS_PER_SEC;
    time_wait_timer->flags = 0;
    time_wait_timer->priv = this;
    time_wait_timer->callback = [](clockevent *ev) {
        tcp_socket *sock = (tcp_socket *) ev->priv;

        // Finally, unref ourselves.
        sock->unref();
    };
}

/**
 * @brief Handle an incoming FIN packet
 *
 * @param buf Packetbuf we got
 */
void tcp_socket::handle_fin(packetbuf *buf)
{
    // Shutdown RD
    shutdown_state |= SHUTDOWN_RD;

    switch (state)
    {
        case tcp_state::TCP_STATE_LAST_ACK:
            // Note: LAST_ACK -> CLOSED means you can just destroy the socket, no problem.
            state = tcp_state::TCP_STATE_CLOSED;
            break;
        case tcp_state::TCP_STATE_SYN_RECEIVED:
        case tcp_state::TCP_STATE_ESTABLISHED:
            send_ack();
            // Move into CLOSE_WAIT (waiting for the client to CLOSE)
            state = tcp_state::TCP_STATE_CLOSE_WAIT;
            break;
        case tcp_state::TCP_STATE_FIN_WAIT_1:
            // Simultaneous close - go to CLOSING and ack it
            send_ack();
            state = tcp_state::TCP_STATE_CLOSING;
            break;
        case tcp_state::TCP_STATE_FIN_WAIT_2:
            send_ack();
            state = tcp_state::TCP_STATE_TIME_WAIT;
            set_time_wait();
            break;
        default:
            break;
    }
}

/**
 * @brief Send an ACK segment
 *
 */
void tcp_socket::send_ack()
{
    tcp_packet pkt{{}, this, TCP_FLAG_ACK, src_addr};
    auto pbuf = pkt.result();

    if (!pbuf)
    {
        sock_err = ENOBUFS;
    }

    if (auto ex = sendpbuf(pbuf.get(), true); ex.has_error())
    {
        sock_err = ex.error();
    }
}

static constexpr uint16_t min_header_size = sizeof(tcp_header);

/**
 * @brief Parse an incoming SYN
 *
 * @param tcphdr Pointer to the tcp header
 * @return True if valid, else false
 */
bool tcp_connection_req::parse_syn(const tcp_header *tcphdr)
{
    uint16_t data_off = ntohs(tcphdr->data_offset_and_flags) >> TCP_DATA_OFFSET_SHIFT;

    window_size = tcphdr->window_size;
    ack_number = ntohl(tcphdr->sequence_number) + 1; // 1 for the SYN

    if (data_off == tcp_header_length_to_data_off(min_header_size))
        return true;

    auto data_off_bytes = tcp_header_data_off_to_length(data_off);

    const uint8_t *options = reinterpret_cast<const uint8_t *>(tcphdr + 1);
    const uint8_t *end = options + (data_off_bytes - min_header_size);

    while (options != end)
    {
        uint8_t opt_byte = *options;

        /* The layout of TCP options is [byte 0 - option kind]
         * [byte 1 - option length ] [byte 2...length - option data]
         */

        if (opt_byte == TCP_OPTION_END_OF_OPTIONS)
            break;

        if (opt_byte == TCP_OPTION_NOP)
        {
            options++;
            continue;
        }

        uint8_t length = *(options + 1);

        switch (opt_byte)
        {
            case TCP_OPTION_MSS:

                mss = *(uint16_t *) (options + 2);
                mss = ntohs(mss);
                break;
            case TCP_OPTION_WINDOW_SCALE:

                uint8_t wss = *(options + 2);
                window_shift = wss;
                window_size = window_size << window_shift;
                break;
        }

        options += length;
    }

    return true;
}

/**
 * @brief Send a SYN-ACK packet
 *
 * @return 0 on success, negative error codes
 */
int tcp_connection_req::send_synack()
{
    auto buf = make_refc<packetbuf>();
    if (!buf)
        return -ENOBUFS;

    if (!buf->allocate_space(MAX_TCP_HEADER_LENGTH))
        return -ENOBUFS;

    buf->reserve_headers(MAX_TCP_HEADER_LENGTH);
    size_t header_len = sizeof(tcp_header);
    // Push any options we need to send
    uint8_t *mss_option = (uint8_t *) buf->push_header(4);
    header_len += 4;
    mss_option[0] = TCP_OPTION_MSS;
    mss_option[1] = 4;
    auto inet_hdr_len = domain == AF_INET ? sizeof(ip_header) : sizeof(ip6hdr);
    uint16_t our_mss = htons(route.nif->mtu - sizeof(tcp_header) - inet_hdr_len);
    memcpy(&mss_option[2], &our_mss, sizeof(our_mss));

    auto tph = (tcp_header *) buf->push_header(sizeof(tcp_header));
    tph->ack_number = htonl(ack_number);
    tph->source_port = from.port;
    tph->dest_port = to.port;
    tph->urgent_pointer = 0;
    tph->window_size = UINT16_MAX;
    tph->sequence_number = htonl(seq_number);
    tph->checksum = 0;
    tph->data_offset_and_flags = htons(
        TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(header_len)) | TCP_FLAG_SYN | TCP_FLAG_ACK);
    tph->checksum = domain == AF_INET
                        ? tcpv4_calculate_checksum(tph, header_len, route.dst_addr.in4.s_addr,
                                                   route.src_addr.in4.s_addr)
                        : tcpv6_calculate_checksum(tph, header_len, route.dst_addr.in6,
                                                   route.src_addr.in6, true);

    return sendpbuf(buf, false);
}

/**
 * @brief Handle a SYN packet
 *
 * @param data Packet handling data
 * @return 0 on success, negative error codes
 */
int tcp_socket::incoming_syn(const packet_handling_data &data)
{
    const auto tcphdr = (const tcp_header *) data.header;
    auto pbuf = data.buffer;
    const auto dstport = tcphdr->dest_port;
    const auto srcport = tcphdr->source_port;

    // Note: SYN requests can hold data, so we're required to hold onto that.

    if (syn_queue_len == backlog)
    {
        // No space in the queue, ignore.
        // Hopefully, we'll have more space when the SYN's retransmission arrives
        return 0;
    }

    inet_sock_address from;
    inet_sock_address to;
    if (data.domain == AF_INET)
    {
        auto iphdr = (ip_header *) pbuf->net_header;
        from = inet_sock_address{in_addr{iphdr->dest_ip}, dstport};
        to = inet_sock_address{in_addr{iphdr->source_ip}, srcport};
    }
    else
    {
        auto iphdr = (ip6hdr *) pbuf->net_header;
        from = inet_sock_address{iphdr->dst_addr, dstport, data.route.nif->if_id};
        to = inet_sock_address{iphdr->src_addr, srcport, data.route.nif->if_id};
    }

    auto ex = get_proto_fam()->route(from, to, data.domain);
    if (ex.has_error())
        return ex.error(); // Weird.

    unique_ptr<tcp_connection_req> req{new tcp_connection_req(ex.value(), data.domain)};
    if (!req)
    {
        // Out of memory :/ Ignore it and hope everything goes well on the retransmit
        return -ENOBUFS;
    }

    req->from = from;
    req->to = to;

    if (!req->parse_syn(tcphdr))
        return 0;

    // Get a random starting sequence number
    req->seq_number = arc4random();

    // Send a SYN-ACK
    req->send_synack();

    auto data_off = TCP_GET_DATA_OFF(ntohs(tcphdr->data_offset_and_flags));
    uint16_t data_size = data.tcp_segment_size - tcp_header_data_off_to_length(data_off);

    // Append this packet to our connection request if it has data
    if (data_size != 0)
    {
        list_add_tail(&pbuf->list_node, &req->received_data);
        pbuf->ref();
    }

    req->seq_number++;

    list_add_tail(&req->list_node, &syn_queue);
    syn_queue_len++;
    req.release();

    return 0;
}

/**
 * @brief Makes an established connection from a connection request
 *
 * @param req Pointer to the tcp connection request
 * @return 0 on success, negative error codes
 */
int tcp_socket::make_connection_from(const tcp_connection_req *req)
{
    src_addr = req->from;
    dest_addr = req->to;

    snd_next = req->seq_number;
    snd_una = snd_next - 1;
    rcv_next = req->ack_number;
    mss = req->mss;
    window_size = req->window_size;
    window_size_shift = req->window_shift;
    route_cache = req->route;
    route_cache_valid = 1;

    if (domain == AF_INET6 && req->domain == AF_INET)
    {
        // This is a v4-on-v6 socket
        ipv4_on_inet6 = 1;
    }

    if (!inet_proto_family::add_socket(this))
    {
        printk("TCP error: Failed to bind on newly accepted socket\n");
        return -EINVAL;
    }

    // Any data we received from the SYN must be put in the rx packet list

    list_for_every_safe (&req->received_data)
    {
        auto pbf = container_of(l, packetbuf, list_node);
        list_remove(&pbf->list_node);
        list_add_tail(&pbf->list_node, &rx_packet_list);
    }

    state = tcp_state::TCP_STATE_ESTABLISHED;

    connected = true;
    bound = true;

    return 0;
}
/**
 * @brief Accept a connection
 *
 * @param req TCP connection request to accept and make into a socket
 * @param data Packet handling data
 * @return 0 on success, negative error codes
 */
int tcp_socket::accept_connection(tcp_connection_req *req, const packet_handling_data &data)
{
    const auto tcphdr = (const tcp_header *) data.header;

    if (ntohl(tcphdr->sequence_number) != req->ack_number ||
        ntohl(tcphdr->ack_number) != req->seq_number)
    {
        // Bad ack.
        return 0;
    }

    if (accept_queue_len == backlog)
    {
        // No space in the accept queue, drop the packet and hope
        // the SYN-ACK transmission kicks in
        return 0;
    }

    ref_guard<tcp_socket> sock{(tcp_socket *) tcp_create_socket(0)};
    if (!sock)
        return -ENOBUFS;

    sock->proto_domain = domain == AF_INET ? ip::v4::get_v4_proto() : ip::v6::get_v6_proto();
    sock->domain = domain;
    sock->proto = proto;
    sock->type = type;

    if (int st = sock->make_connection_from(req); st < 0)
        return st;

    list_remove(&req->list_node);
    syn_queue_len--;
    delete req;

    list_add_tail(&sock->accept_node, &accept_queue);
    wait_queue_wake_all(&accept_wq);
    sock.release();
    accept_queue_len++;

    return 0;
}

/**
 * @brief Accept a connection following an ACK
 *
 * @param data Packet handling data
 * @return 0 on success, negative error codes
 */
int tcp_socket::handle_synack_ack(const packet_handling_data &data)
{
    const auto pbuf = data.buffer;
    const auto tcphdr = (const tcp_header *) data.header;

    inet_sock_address from;
    inet_sock_address to;
    bool ipv4 = data.domain == AF_INET;
    if (ipv4)
    {
        auto iphdr = (ip_header *) pbuf->net_header;
        from = inet_sock_address{in_addr{iphdr->dest_ip}, tcphdr->dest_port};
        to = inet_sock_address{in_addr{iphdr->source_ip}, tcphdr->source_port};
    }
    else
    {
        auto iphdr = (ip6hdr *) pbuf->net_header;
        from = inet_sock_address{iphdr->dst_addr, tcphdr->dest_port, data.route.nif->if_id};
        to = inet_sock_address{iphdr->src_addr, tcphdr->source_port, data.route.nif->if_id};
    }

    list_for_every_safe (&syn_queue)
    {
        tcp_connection_req *r = container_of(l, tcp_connection_req, list_node);
        if (r->to.equals(to, ipv4) && r->from.equals(from, ipv4))
        {
            return accept_connection(r, data);
        }
    }

    return 0;
}

/**
 * @brief Handle packet recv on LISTEN
 *
 * @param data Packet handling data
 * @return 0 on success, negative error codes
 */
int tcp_socket::do_listen_rcv(const packet_handling_data &data)
{
    const auto tcphdr = (const tcp_header *) data.header;
    auto flags = htons(tcphdr->data_offset_and_flags) & 0xff;

    if (flags == TCP_FLAG_SYN)
    {
        // Attempt to store this in our syn queue
        return incoming_syn(data);
    }

    if (flags == TCP_FLAG_ACK)
    {
        return handle_synack_ack(data);
    }

    return 0;
}

/**
 * @brief Handle packet recv on ESTABLISHED
 *
 * @param data Packet handling data
 * @return 0 on success, negative error codes
 */
int tcp_socket::do_established_rcv(const packet_handling_data &data)
{
    const auto tcphdr = (const tcp_header *) data.header;
    auto flags = htons(tcphdr->data_offset_and_flags);
    int drop = 0;

    if (!(flags & TCP_FLAG_ACK))
    {
        // Every segment received after established needs to have ACK set
        return TCP_DROP_NOACK;
    }

    if (flags & TCP_FLAG_SYN)
    {
        // SYN is not a valid flag in this state
        return TCP_DROP_GENERIC;
    }

    /* ack_number holds the other side of the connection's sequence number */
    auto starting_seq_number = ntohl(data.header->sequence_number);
    auto data_off = TCP_GET_DATA_OFF(ntohs(data.header->data_offset_and_flags));
    uint16_t data_size = data.tcp_segment_size - tcp_header_data_off_to_length(data_off);
    uint32_t seqs = data_size;
    if (flags & TCP_FLAG_FIN)
        seqs++;

    rcv_next = starting_seq_number + seqs;

    // Send a reset if we got data and we're not queueing data anymore
    if (shutdown_state & SHUTDOWN_RD && data_size != 0)
    {
        reset();
        send_reset();
        return 0;
    }

    if (flags & TCP_FLAG_FIN)
    {
        handle_fin(data.buffer);
        return 0;
    }

    if (data_size || flags & TCP_FLAG_FIN)
    {
        // If this wasn't a FIN packet, it has data
        // so append it to the receive buffers
        if (!(flags & TCP_FLAG_FIN))
        {
            auto buf = data.buffer;
            append_inet_rx_pbuf(buf);
        }

        // Now ack it
        send_ack();
    }
    else if (data_size == 0 && (flags & 0xff) == TCP_FLAG_ACK)
    {
        // Process the ACK
        drop = do_ack(data.buffer);
    }

    if (list_is_empty(&pending_out_packets))
    {
        // Try to send any possible pending packets
        if (int st = try_to_send(); st < 0)
            sock_err = -st;
    }

    return drop;
}

/**
 * @brief Append a packetbuf packet to the backlog
 *
 * @param buf packetbuf
 */
void tcp_socket::append_backlog(packetbuf *buf)
{
    buf->ref();
    add_backlog(&buf->list_node);
}

/**
 * @brief Handle TCP socket backlog (pending segments)
 *
 */
void tcp_socket::handle_backlog()
{
    // For every pending segment, get its packetbuf. Then figure out packet_handling_data and ship
    // it to the proper handling functions.

    list_for_every_safe (&socket_backlog)
    {
        auto pbuf = container_of(l, packetbuf, list_node);

        sockaddr_in_both both;

        auto header = (tcp_header *) pbuf->transport_header;
        uint16_t tcp_payload_len;

        if (pbuf->domain == AF_INET)
        {
            auto ip_header = (struct ip_header *) pbuf->net_header;
            ipv4_to_sockaddr(ip_header->source_ip, header->source_port, both.in4);
            tcp_payload_len =
                static_cast<uint16_t>(ntohs(ip_header->total_len) - ip_header_length(ip_header));
        }
        else if (pbuf->domain == AF_INET6)
        {
            auto ip_header = (struct ip6hdr *) pbuf->net_header;
            ipv6_to_sockaddr(ip_header->src_addr, header->source_port, both.in6);
            tcp_payload_len = ntohs(ip_header->payload_length);
        }
        else
        {
            panic("invalid domain");
        }

        const tcp_socket::packet_handling_data handle_data{pbuf,  header,       tcp_payload_len,
                                                           &both, pbuf->domain, pbuf->route};
        list_remove(&pbuf->list_node);

        handle_segment(handle_data);

        pbuf->unref();
    }

    if (proto_needs_work)
    {
        if (retrans_pending)
        {
            retransmit_segments();
            retrans_pending = 0;
        }

        proto_needs_work = false;
    }
}

int tcp_socket::handle_segment(const tcp_socket::packet_handling_data &data)
{
    if (state == tcp_state::TCP_STATE_SYN_SENT)
        return do_receive_syn_sent(data);

    // All these states share a substancial amount of code.
    switch (state)
    {
        case tcp_state::TCP_STATE_FIN_WAIT_1:
        case tcp_state::TCP_STATE_FIN_WAIT_2:
        case tcp_state::TCP_STATE_CLOSE_WAIT:
        case tcp_state::TCP_STATE_CLOSING:
        case tcp_state::TCP_STATE_LAST_ACK:
        case tcp_state::TCP_STATE_ESTABLISHED:
            return do_established_rcv(data);
        default:
            break;
    }

    if (state == tcp_state::TCP_STATE_LISTEN)
        return do_listen_rcv(data);
    return -EINVAL;
}

int tcp_socket::handle_packet(const tcp_socket::packet_handling_data &data)
{
    auto data_off = TCP_GET_DATA_OFF(ntohs(data.header->data_offset_and_flags));
    uint16_t header_size = tcp_header_data_off_to_length(data_off);

    if (data.tcp_segment_size < header_size)
        return TCP_DROP_BAD_PACKET;
#if 0
	printk("segment size: %u\n", data.tcp_segment_size);
	printk("header size: %u\n", header_size);
	printk("ack number %u\n", ack_number);
#endif

    uint16_t data_size = data.tcp_segment_size - header_size;
    data.buffer->data += header_size;
    cul::slice<uint8_t> buf{(uint8_t *) data.header + header_size, data_size};

    auto flags = htons(data.header->data_offset_and_flags);

    window_size = ntohs(data.header->window_size) << window_size_shift;

    if (flags & TCP_FLAG_RST)
    {
        reset();
        return 0;
    }

    scoped_hybrid_lock<true> hlock{socket_lock, this};

    if (!socket_lock.is_ours())
    {
        append_backlog(data.buffer);
        return 0;
    }

    return handle_segment(data);
}

int tcp_send_rst_no_socket(const inet_route &route, in_port_t dstport, in_port_t srcport,
                           int domain, netif *nif)
{
    auto buf = make_refc<packetbuf>();
    if (!buf)
        return -ENOMEM;

    auto ip_size = domain == AF_INET ? sizeof(ip_header) : sizeof(ip6_hdr);

    if (!buf->allocate_space(MAX_TCP_HEADER_LENGTH + ip_size))
        return -ENOMEM;

    buf->reserve_headers(MAX_TCP_HEADER_LENGTH + ip_size);

    auto hdr = (tcp_header *) buf->push_header(sizeof(tcp_header));

    memset(hdr, 0, sizeof(tcp_header));
    hdr->dest_port = srcport;
    hdr->source_port = dstport;
    hdr->data_offset_and_flags =
        htons(TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(sizeof(tcp_header))) | TCP_FLAG_RST);
    hdr->checksum =
        domain == AF_INET
            ? tcpv4_calculate_checksum(hdr, sizeof(tcp_header), route.dst_addr.in4.s_addr,
                                       route.src_addr.in4.s_addr)
            : tcpv6_calculate_checksum(hdr, sizeof(tcp_header), route.dst_addr.in6,
                                       route.src_addr.in6, true);

    inet_sock_address from;
    inet_sock_address to;
    if (domain == AF_INET)
    {
        from = inet_sock_address{route.dst_addr.in4, dstport};
        to = inet_sock_address{route.src_addr.in4, srcport};
    }
    else
    {
        from = inet_sock_address{route.dst_addr.in6, dstport, route.nif->if_id};
        to = inet_sock_address{route.src_addr.in6, srcport, route.nif->if_id};
    }

    auto actual_route = (domain == AF_INET ? ip::v4::get_v4_proto() : ip::v6::get_v6_proto())
                            ->route(from, to, domain);

    if (actual_route.has_error())
        return actual_route.error();

    iflow flow{actual_route.value(), IPPROTO_TCP, domain == AF_INET6};

    if (domain == AF_INET)
        return ip::v4::send_packet(flow, buf.get());
    else
        return ip::v6::send_packet(flow, buf.get());
}

int tcp_handle_packet(const inet_route &route, packetbuf *buf)
{
    auto ip_header = (struct ip_header *) buf->net_header;
    int st = 0;
    auto header = reinterpret_cast<tcp_header *>(buf->data);

    if (!validate_tcp_packet(header, buf->length())) [[unlikely]]
        return TCP_DROP_BAD_PACKET;

    buf->transport_header = (unsigned char *) header;

    // TCP connections don't run on broadcast/mcast
    if (route.flags & (INET4_ROUTE_FLAG_BROADCAST | INET4_ROUTE_FLAG_MULTICAST))
        return TCP_DROP_BAD_PACKET;

    ref_guard<tcp_socket> socket{inet_resolve_socket_conn<tcp_socket>(
        ip_header->source_ip, header->source_port, header->dest_port, IPPROTO_TCP, route.nif,
        &tcp_proto)};
    uint16_t tcp_payload_len =
        static_cast<uint16_t>(ntohs(ip_header->total_len) - ip_header_length(ip_header));

    if (!socket)
    {
        auto flags = htons(header->data_offset_and_flags);

        if (!(flags & TCP_FLAG_RST))
            tcp_send_rst_no_socket(route, header->dest_port, header->source_port, AF_INET,
                                   route.nif);
        /* No socket bound, bad packet. */
        return TCP_DROP_NOSOCK;
    }

    sockaddr_in_both both;
    ipv4_to_sockaddr(ip_header->source_ip, header->source_port, both.in4);

    const tcp_socket::packet_handling_data handle_data{buf,   header,  tcp_payload_len,
                                                       &both, AF_INET, route};

    st = socket->handle_packet(handle_data);
    if (st != 0)
        pr_info("socket drop %d\n", st);
    return st;
}

int tcp6_handle_packet(const inet_route &route, packetbuf *buf)
{
    auto ip_header = (struct ip6hdr *) buf->net_header;
    int st = 0;
    auto header = reinterpret_cast<tcp_header *>(buf->data);

    if (!validate_tcp_packet(header, buf->length())) [[unlikely]]
        return TCP_DROP_BAD_PACKET;

    buf->transport_header = (unsigned char *) header;

    // TCP connections don't run on broadcast/mcast
    if (route.flags & (INET4_ROUTE_FLAG_BROADCAST | INET4_ROUTE_FLAG_MULTICAST))
        return TCP_DROP_BAD_PACKET;

    ref_guard<tcp_socket> socket{inet6_resolve_socket_conn<tcp_socket>(
        ip_header->src_addr, header->source_port, ip_header->dst_addr, header->dest_port,
        IPPROTO_TCP, route.nif, &tcp_proto)};
    uint16_t tcp_payload_len = ntohs(ip_header->payload_length);

    if (!socket)
    {
        auto flags = htons(header->data_offset_and_flags);

        if (!(flags & TCP_FLAG_RST))
            tcp_send_rst_no_socket(route, header->dest_port, header->source_port, AF_INET6,
                                   route.nif);
        /* No socket bound, bad packet. */
        return TCP_DROP_NOSOCK;
    }

    sockaddr_in_both both;
    ipv6_to_sockaddr(ip_header->src_addr, header->source_port, both.in6);

    const tcp_socket::packet_handling_data handle_data{buf,   header,   tcp_payload_len,
                                                       &both, AF_INET6, route};

    st = socket->handle_packet(handle_data);

    return st;
}

uint16_t tcpv4_calculate_checksum(const tcp_header *header, uint16_t packet_length, uint32_t srcip,
                                  uint32_t dstip, bool calc_data)
{
    uint32_t proto = ((packet_length + IPPROTO_TCP) << 8);
    uint16_t buf[2];
    memcpy(&buf, &proto, sizeof(buf));

    auto r = __ipsum_unfolded(&srcip, sizeof(srcip), 0);
    r = __ipsum_unfolded(&dstip, sizeof(dstip), r);
    r = __ipsum_unfolded(buf, sizeof(buf), r);

    if (calc_data)
        r = __ipsum_unfolded(header, packet_length, r);

    return ipsum_fold(r);
}

uint16_t tcpv6_calculate_checksum(const tcp_header *header, uint16_t packet_length,
                                  const in6_addr &srcip, const in6_addr &dstip, bool calc_data)
{
    uint32_t proto = htonl(IPPROTO_TCP);
    uint32_t pseudo_len = htonl(packet_length);

    auto r = __ipsum_unfolded(&srcip, sizeof(srcip), 0);
    r = __ipsum_unfolded(&dstip, sizeof(dstip), r);
    r = __ipsum_unfolded(&pseudo_len, sizeof(pseudo_len), r);
    r = __ipsum_unfolded(&proto, sizeof(proto), r);
    assert(header->checksum == 0);

    if (calc_data)
        r = __ipsum_unfolded(header, packet_length, r);

    return ipsum_fold(r);
}

uint16_t tcp_packet::options_length() const
{
    uint16_t len = 0;
    list_for_every_safe (&option_list)
    {
        tcp_option *opt = container_of(l, tcp_option, list_node);
        len += opt->length;
    }

    /* TCP options have padding to make sure it ends on a 32-bit boundary */
    if (len & (4 - 1))
        len = ALIGN_TO(len, 4);

    return len;
}

void tcp_packet::put_options(char *opts)
{
    list_for_every (&option_list)
    {
        tcp_option *opt = container_of(l, tcp_option, list_node);

        opts[0] = opt->kind;
        opts[1] = opt->length;
        /* Take off 2 bytes to account for the overhead of kind and length */
        memcpy(&opts[2], &opt->data, opt->length - 2);
        opts += opt->length;
    }
}

ref_guard<packetbuf> tcp_packet::result()
{
    buf = make_refc<packetbuf>();
    if (!buf)
        return {};

    if (!buf->allocate_space(payload.size_bytes() + socket->get_headers_len() +
                             MAX_TCP_HEADER_LENGTH))
        return {};
    buf->reserve_headers(socket->get_headers_len() + MAX_TCP_HEADER_LENGTH);

    uint16_t options_len = options_length();
    auto header_size = sizeof(tcp_header) + options_len;

    tcp_header *header = (tcp_header *) buf->push_header(header_size);

    buf->transport_header = (unsigned char *) header;

    memset(header, 0, header_size);

    auto &dest = socket->daddr();

    auto data_off = TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(header_size));

    /* Assume the max window size as the window size, for now */
    header->window_size = htons(socket->our_window_size);
    header->source_port = socket->saddr().port;
    header->sequence_number = htonl(socket->sequence_nr());
    header->data_offset_and_flags = htons(data_off | flags);
    header->dest_port = dest.port;
    header->urgent_pointer = 0;

    if (flags & TCP_FLAG_ACK)
        header->ack_number = htonl(socket->acknowledge_nr());
    else
        header->ack_number = 0;

    put_options(reinterpret_cast<char *>(header + 1));

    auto length = payload.size_bytes();

    if (length != 0)
    {
        auto ptr = buf->put(length);
        memcpy(ptr, payload.data(), length);
    }

    auto &route = socket->route_cache;
    auto nif = route.nif;

    bool need_csum = true;

    if (socket->can_offload_csum(nif, buf.get()))
    {
        buf->csum_offset = &header->checksum;
        buf->csum_start = (unsigned char *) header;
        buf->needs_csum = 1;
        need_csum = false;
    }

    // Ugly because we're out of the socket class so effective_domain() is a myth here.
    header->checksum =
        socket->effective_domain() == AF_INET6
            ? tcp_calculate_checksum<AF_INET6>(header, static_cast<uint16_t>(header_size + length),
                                               route.src_addr, route.dst_addr, need_csum)
            : tcp_calculate_checksum<AF_INET>(header, static_cast<uint16_t>(header_size + length),
                                              route.src_addr, route.dst_addr, need_csum);

    starting_seq_number = socket->sequence_nr();
    uint32_t seqs = length;
    if (flags & TCP_FLAG_SYN)
        seqs++;

    socket->sequence_nr() += seqs;

    return buf;
}

bool tcp_socket::parse_options(tcp_header *packet)
{
    auto flags = ntohs(packet->data_offset_and_flags);

    bool syn_set = flags & TCP_FLAG_SYN;
    (void) syn_set;

    uint16_t data_off = flags >> TCP_DATA_OFFSET_SHIFT;

    if (data_off == tcp_header_length_to_data_off(min_header_size))
        return true;

    auto data_off_bytes = tcp_header_data_off_to_length(data_off);

    uint8_t *options = reinterpret_cast<uint8_t *>(packet + 1);
    uint8_t *end = options + (data_off_bytes - min_header_size);

    while (options != end)
    {
        uint8_t opt_byte = *options;

        /* The layout of TCP options is [byte 0 - option kind]
         * [byte 1 - option length ] [byte 2...length - option data]
         */

        if (opt_byte == TCP_OPTION_END_OF_OPTIONS)
            break;

        if (opt_byte == TCP_OPTION_NOP)
        {
            options++;
            continue;
        }

        uint8_t length = *(options + 1);

        switch (opt_byte)
        {
            case TCP_OPTION_MSS:
                if (!syn_set)
                    return false;

                mss = *(uint16_t *) (options + 2);
                mss = ntohs(mss);
                break;
            case TCP_OPTION_WINDOW_SCALE:
                if (!syn_set)
                    return false;

                uint8_t wss = *(options + 2);
                window_size_shift = wss;
                break;
        }

        options += length;
    }

    return true;
}

constexpr uint16_t tcp_headers_overhead = sizeof(struct tcp_header);

void tcp_out_timeout(clockevent *ev)
{
    tcp_socket *t = (tcp_socket *) ev->priv;
    t->do_retransmit();
}

void tcp_socket::do_retransmit()
{
    socket_lock.lock_bh();
    if (!socket_lock.is_ours())
    {
        retrans_pending = 1;
        proto_needs_work = true;
    }
    else
        retransmit_segments();
    socket_lock.unlock_bh();
}

void tcp_socket::retransmit_segments()
{
    if (retransmit_try == tcp_retransmission_max)
    {
        /* Send a RST and give up */
        send_reset();
        retrans_active = false;
        return;
    }

    /* Go through pending out, resubmit, and reschedule a new timer */
    list_for_every (&pending_out_packets)
    {
        tcp_pending_out *out = list_head_cpp<tcp_pending_out>::self_from_list_head(l);
        send_segment(out->buf.get());
    }

    hrtime_t timeout = 200 * NS_PER_MS;
    retransmit_try++;
    for (int i = 0; i < retransmit_try; i++)
        timeout *= 2;
    start_retransmit_timer(timeout);
}

/**
 * @brief Handle a SYN-ACK timeout
 *
 * @param ev Clockevent passed by the timer subsystem
 */
void tcp_out_synack_timeout(clockevent *ev)
{
    tcp_pending_out *t = (tcp_pending_out *) ev->priv;

    if (t->acked)
    {
        ev->flags &= ~CLOCKEVENT_FLAG_PULSE;
        return;
    }

    if (t->transmission_try == tcp_retransmission_max)
    {
        wait_queue_wake_all(&t->wq);
        ev->flags &= ~CLOCKEVENT_FLAG_PULSE;
        if (t->fail)
            t->fail(t);
        return;
    }

    t->transmission_try++;
    tcp_socket *sock = t->sock;

    iflow flow{t->req->route, IPPROTO_TCP, t->req->domain == AF_INET6};

    // Since the packet has already been pre-prepared by the network stack
    // we can just send it straight through the network interface
    int st = netif_send_packet(flow.nif, t->buf.get());

    if (st < 0)
    {
        // If something failed, signal an error and stop retransmitting.
        sock->sock_err = -st;
        wait_queue_wake_all(&t->wq);
        ev->flags &= ~CLOCKEVENT_FLAG_PULSE;
        if (t->fail)
            t->fail(t);
        return;
    }

    hrtime_t next_timeout = 200;
    for (unsigned int i = 0; i < t->transmission_try; i++)
    {
        next_timeout *= 2;
    }

    ev->deadline = clocksource_get_time() + next_timeout * NS_PER_MS;
}

void tcp_socket::start_retransmit_timer(hrtime_t timeout)
{
    retransmit_timer.callback = tcp_out_timeout;
    retransmit_timer.flags = 0;
    retransmit_timer.deadline = clocksource_get_time() + timeout;
    retransmit_timer.priv = this;
    timer_queue_clockevent(&retransmit_timer);
}

void tcp_socket::start_retransmit()
{
    /* Socket lock must be held */
    retransmit_try = 0;
    start_retransmit_timer(200 * NS_PER_MS);
    retrans_active = true;
}

void tcp_socket::stop_retransmit()
{
    retransmit_try = 0;
    if (retrans_active)
        timer_cancel_event(&retransmit_timer);
    retrans_active = false;
}

/**
 * @brief Sends a packetbuf
 *
 * @param buf Packetbuf to send
 * @param noack True if no ack is needed
 * @return Expected of a ref_guard to a tcp_pending_out, or a negative error code
 */
expected<ref_guard<tcp_pending_out>, int> tcp_socket::sendpbuf(packetbuf *buf, bool noack)
{
    const auto eff_domain = effective_domain();
    iflow flow{route_cache, IPPROTO_TCP, eff_domain == AF_INET6};
    ref_guard<tcp_pending_out> pending;
    if (!noack)
    {
        scoped_lock g{pending_out_lock};

        pending = make_refc<tcp_pending_out>(this);
        if (!pending)
        {
            return unexpected{-ENOBUFS};
        }

        buf->ref();
        pending->buf = ref_guard{buf};
        append_pending_out(pending.get());
    }

    int st = -EINVAL;
    if (eff_domain == AF_INET)
        st = ip::v4::send_packet(flow, buf);
    else if (eff_domain == AF_INET6)
        st = ip::v6::send_packet(flow, buf);

    if (st < 0)
        return unexpected{st};

    if (noack)
        return ref_guard<tcp_pending_out>{};

    if (!retrans_active)
        start_retransmit();

    return pending;
}

/**
 * @brief Sends a packetbuf
 *
 * @param buf Packetbuf to send
 * @param noack True if no ack is needed
 * @return 0 on success,negative error codes
 */
int tcp_connection_req::sendpbuf(ref_guard<packetbuf> buf, bool noack)
{
    const auto eff_domain = domain;
    iflow flow{route, IPPROTO_TCP, eff_domain == AF_INET6};
    ref_guard<tcp_pending_out> pending;
    if (!noack)
    {
        pending = make_refc<tcp_pending_out>(this);
        if (!pending)
            return -ENOBUFS;

        pending->buf = buf;
        syn_ack_pending = pending;
    }

    int st = -EINVAL;
    if (eff_domain == AF_INET)
        st = ip::v4::send_packet(flow, buf.get());
    else if (eff_domain == AF_INET6)
        st = ip::v6::send_packet(flow, buf.get());

    if (st < 0)
        return st;

    return 0;
}

/**
 * @brief Fail a connection attempt
 *
 */
void tcp_socket::conn_fail(int error)
{
    sock_err = error;
    state = tcp_state::TCP_STATE_CLOSED;
    wait_queue_wake_all(&conn_wq);
}

int tcp_socket::start_handshake(netif *nif, int flags)
{
    tcp_packet first_packet{{}, this, TCP_FLAG_SYN, src_addr};
    first_packet.set_packet_flags(TCP_PACKET_FLAG_ON_STACK | TCP_PACKET_FLAG_WANTS_ACK_HEADER);

    tcp_option opt{TCP_OPTION_MSS, 4};

    uint16_t our_mss = nif->mtu - tcp_headers_overhead - get_headers_len();
    opt.data.mss = htons(our_mss);

    first_packet.append_option(&opt);

    auto buf = first_packet.result();

    if (!buf)
        return -ENOBUFS;

    auto ex = sendpbuf(buf.get());

    if (ex.has_error())
        return ex.error();

    auto val = ex.value();

    state = tcp_state::TCP_STATE_SYN_SENT;

    // TODO: sendpbuf should set fail and done_callback directly, as to avoid races
    if (flags & O_NONBLOCK)
    {
        val->fail = [](tcp_pending_out *pending) {
            pending->sock->conn_fail(pending->reset ? ECONNRESET : ETIMEDOUT);
        };

        val->done_callback = [](tcp_pending_out *pending) { pending->sock->finish_conn(); };

        connection_pending = true;

        return -EINPROGRESS;
    }

    int st = val->wait();

    if (st < 0)
        return st;

    if (st < 0)
    {
        /* wait_for_ack returns the error code in st */
        state = tcp_state::TCP_STATE_CLOSED;
        return st;
    }

    return 0;
}

/**
 * @brief Finish a connection
 *
 */
void tcp_socket::finish_conn()
{
    // Race?
    state = tcp_state::TCP_STATE_ESTABLISHED;
    connection_pending = false;
    connected = true;
    sock_err = 0;
    wait_queue_wake_all(&conn_wq);
}

int tcp_socket::start_connection(int flags)
{
    snd_next = snd_una = arc4random();

    auto fam = get_proto_fam();
    auto result = fam->route(src_addr, dest_addr, domain);

    if (result.has_error())
        return result.error();

    route_cache = result.value();

    if (route_cache.flags & (INET4_ROUTE_FLAG_BROADCAST | INET4_ROUTE_FLAG_MULTICAST))
    {
        // Not a valid TCP connection
        // Linux seems to return ENETUNREACH here.
        return -ENETUNREACH;
    }

    route_cache_valid = 1;

    our_window_size = UINT16_MAX;

    int st = start_handshake(route_cache.nif, flags);
    if (st < 0)
        return st;

    finish_conn();

    return st;
}

int tcp_socket::connect(struct sockaddr *addr, socklen_t addrlen, int flags)
{
    if (!bound)
    {
        auto fam = get_proto_fam();
        int st = fam->bind_any(this);
        if (st < 0)
            return st;
    }

    if (connected)
        return -EISCONN;

    if (connection_pending)
        return -EALREADY;

    if (!validate_sockaddr_len_pair(addr, addrlen))
        return -EINVAL;

    auto [dst, addr_domain] = sockaddr_to_isa(addr);

    bool on_ipv4_mode = addr_domain == AF_INET && domain == AF_INET6;

    dest_addr = dst;

    ipv4_on_inet6 = on_ipv4_mode;

    return start_connection(flags);
}

/**
 * @brief Prepare segment for sending
 *
 * @param buf Packetbuf
 */
void tcp_socket::prepare_segment(packetbuf *pbf)
{
    unsigned int flags = TCP_FLAG_ACK;
    auto segment_len = pbf->length();
    pbf->tpi.seq = snd_next;
    pbf->tpi.seq_len = segment_len;
    snd_next += segment_len;

    if (flags & TCP_FLAG_FIN)
    {
        pbf->tpi.seq_len++;
        snd_next++;
    }
}

int tcp_socket::append_data(const iovec *vec, size_t vec_len, size_t mss)
{
    size_t read_in_vec = 0;
    packetbuf *packet = nullptr;
    unsigned int packet_len = 0;

    if (list_is_empty(pending_out.get_packet_list()))
        goto alloc_append;

    packet = pending_out.get_tail();
    if (!vec_len)
        return 0;

    while ((packet_len = packet->length()) < mss)
    {
        /* OOOH, we've got some room, let's expand! */
        const uint8_t *ubuf = (uint8_t *) vec->iov_base + read_in_vec;
        auto len = vec->iov_len - read_in_vec;
        unsigned int to_expand = cul::clamp(len, mss - packet_len);
        ssize_t st = packet->expand_buffer(ubuf, to_expand);

        if (st < 0)
            return -ENOBUFS;

        packet->tpi.seq_len += to_expand;
        read_in_vec += st;
        if (read_in_vec == vec->iov_len)
        {
            vec++;
            read_in_vec = 0;
            vec_len--;
        }

        /* Good, we're finished. */
        if (!vec_len)
            return 0;
    }

alloc_append:
    return alloc_and_append(vec, vec_len, mss, read_in_vec);
}

int tcp_socket::alloc_and_append(const iovec *vec, size_t vec_len, size_t mss, size_t skip_first)
{
    size_t added_from_vec = 0;
    size_t vec_nr = 0;
    while (vec_len)
    {
        packetbuf *packet = new packetbuf;
        if (!packet)
            return -ENOBUFS;

        size_t iov_len = vec->iov_len;
        if (vec_nr == 0)
        {
            // We might be creating a new packet from a partial iov that already filled
            // some other packet in the list.

            iov_len -= skip_first;
        }

        unsigned long max_payload = cul::clamp(iov_len - added_from_vec, mss);
        unsigned long to_alloc = max_payload + mss + PACKET_MAX_HEAD_LENGTH;

        auto ubuf = (const uint8_t *) vec->iov_base + added_from_vec;

        if (!packet->allocate_space(to_alloc))
        {
            delete packet;
            return -ENOBUFS;
        }

        packet->reserve_headers(PACKET_MAX_HEAD_LENGTH);
        auto st = packet->expand_buffer(ubuf, max_payload);

        prepare_segment(packet);
        assert((size_t) st == max_payload);
        added_from_vec += max_payload;
        list_add_tail(&packet->list_node, pending_out.get_packet_list());

        if (added_from_vec == iov_len)
        {
            added_from_vec = 0;
            vec_len--;
            vec++;
            vec_nr++;
        }
    }

    return 0;
}

ssize_t tcp_socket::queue_data(iovec *vec, int vlen, size_t len)
{
    return append_data(vec, vlen, mss);
}

ssize_t tcp_socket::get_max_payload_len(uint16_t tcp_header_len)
{
    return 0;
}

/**
 * @brief Checks if we can send a packet according to nagle's algorithm
 *
 * @param buf Packetbuf to check
 * @return True if possible, else false.
 */
bool tcp_socket::nagle_can_send(packetbuf *buf)
{
    // Note: pending_out_packets contains the packets that await an ACK (retransmission is done on
    // this list)
    return (other_window() >= mss && buf->length() == mss) || list_is_empty(&pending_out_packets);
}

packetbuf *tcp_socket::clone_for_send(packetbuf *buf)
{
    if (buf->transport_header)
    {
        /* Oh? We have a TCP header already, we're supposed to send this out. */
        /* TODO: no. */
        buf->ref();
        return buf;
    }

    packetbuf *pbf = packetbuf_clone(buf);
    if (!pbf)
        return nullptr;

    tcp_header *header = (tcp_header *) pbf->push_header(sizeof(tcp_header));
    pbf->transport_header = (unsigned char *) header;

    memset(header, 0, sizeof(tcp_header));

    auto &dest = daddr();

    auto data_off = TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(sizeof(tcp_header)));

    /* Assume the max window size as the window size, for now */
    header->window_size = htons(our_window_size);
    header->source_port = saddr().port;
    header->sequence_number = htonl(pbf->tpi.seq);
    header->data_offset_and_flags = htons(data_off | TCP_FLAG_ACK);
    header->dest_port = dest.port;
    header->urgent_pointer = 0;

    auto &route = route_cache;
    auto nif = route.nif;

    bool need_csum = true;

    if (can_offload_csum(nif, pbf))
    {
        pbf->csum_offset = &header->checksum;
        pbf->csum_start = (unsigned char *) header;
        pbf->needs_csum = 1;
        need_csum = false;
    }

    header->ack_number = htonl(acknowledge_nr());
    header->checksum = call_based_on_inet(tcp_calculate_checksum, header,
                                          static_cast<uint16_t>(sizeof(tcp_header) + buf->length()),
                                          route.src_addr, route.dst_addr, need_csum);

    return pbf;
}

/**
 * @brief Sends a data segment
 *
 * @param buf Packetbuf to send
 * @return 0 on success, negative error codes
 */
int tcp_socket::send_segment(packetbuf *buf)
{
    // TODO: options?
    auto segment_len = buf->length();
    packetbuf *pbf = clone_for_send(buf);
    if (!pbf)
        return -ENOMEM;

    if (WARN_ON_ONCE(segment_len > mss))
        pr_err("tcp: segment size %u > mss %u\n", segment_len, mss);

    auto ex = sendpbuf(pbf);
    pbf->unref();
    if (ex.has_error())
        return ex.error();

    // Send went fine, decrement the window size
    window_size -= segment_len;
    return 0;
}

/**
 * @brief Try to send data
 *
 * @return 0 on success, negative error codes
 */
int tcp_socket::try_to_send()
{
    auto packet_list = pending_out.get_packet_list();

    list_for_every_safe (packet_list)
    {
        auto pbf = container_of(l, packetbuf, list_node);

        // Need to stop: the window doesn't allow us to send data
        if (other_window() < pbf->length())
        {
            break;
        }

        // If we're on nagle and nagle doesn't allow us to send, stop sending
        if (nagle_enabled && !nagle_can_send(pbf))
        {
            break;
        }

        // Pre-remove it, because if everything is successful
        // it'll get appended to another list
        list_remove(&pbf->list_node);

        int st = send_segment(pbf);

        // Error, re-append
        if (st < 0)
        {
            list_add_tail(&pbf->list_node, packet_list);
            return sock_err;
        }
    }

    return 0;
}

ssize_t tcp_socket::sendmsg(const msghdr *msg, int flags)
{
    if (msg->msg_name)
        return -EISCONN;

    scoped_hybrid_lock g{socket_lock, this};

    if (!can_send())
        return -ENOTCONN;

    CONSUME_SOCK_ERR;

    auto len = iovec_count_length(msg->msg_iov, msg->msg_iovlen);

    if (len < 0)
        return len;

    auto st = queue_data(msg->msg_iov, msg->msg_iovlen, (size_t) len);
    if (st < 0)
        return st;

    if (int _st = try_to_send(); _st < 0)
        return _st;

    return len;
}

void tcp_socket::append_pending_out(tcp_pending_out *pckt)
{
    list_add_tail(&pckt->node, &pending_out_packets);

    /* Don't forget to ref the packet! */
    pckt->ref();
}

void tcp_socket::remove_pending_out(tcp_pending_out *pkt)
{
    list_remove(&pkt->node);

    /* And also don't forget to unref it back! */
    pkt->unref();
}

int tcp_socket::setsockopt(int level, int opt, const void *optval, socklen_t optlen)
{
    if (level == SOL_SOCKET)
        return setsockopt_socket_level(opt, optval, optlen);

    if (is_inet_level(level))
        return setsockopt_inet(level, opt, optval, optlen);

    return -ENOPROTOOPT;
}

int tcp_socket::getsockopt(int level, int opt, void *optval, socklen_t *optlen)
{
    if (level == SOL_SOCKET)
        return getsockopt_socket_level(opt, optval, optlen);
    return -ENOPROTOOPT;
}

struct socket *tcp_create_socket(int type)
{
    auto sock = new tcp_socket();

    if (sock)
    {
        sock->proto_info = &tcp_proto;
    }

    return sock;
}

/**
 * @brief TCP shutdown(wr) state transition table
 *
 */
static tcp_state post_wr_shutdown_states[] = {
    [(int) tcp_state::TCP_STATE_LISTEN] = tcp_state::TCP_STATE_CLOSED,
    [(int) tcp_state::TCP_STATE_SYN_SENT] = tcp_state::TCP_STATE_CLOSED,
    [(int) tcp_state::TCP_STATE_SYN_RECEIVED] = tcp_state::TCP_STATE_FIN_WAIT_1,
    [(int) tcp_state::TCP_STATE_ESTABLISHED] = tcp_state::TCP_STATE_FIN_WAIT_1,
    [(int) tcp_state::TCP_STATE_FIN_WAIT_1] = tcp_state::TCP_STATE_FIN_WAIT_1,
    [(int) tcp_state::TCP_STATE_FIN_WAIT_2] = tcp_state::TCP_STATE_FIN_WAIT_2,
    [(int) tcp_state::TCP_STATE_CLOSE_WAIT] = tcp_state::TCP_STATE_LAST_ACK,
    [(int) tcp_state::TCP_STATE_CLOSING] = tcp_state::TCP_STATE_CLOSING,
    [(int) tcp_state::TCP_STATE_LAST_ACK] = tcp_state::TCP_STATE_LAST_ACK,
    [(int) tcp_state::TCP_STATE_TIME_WAIT] = tcp_state::TCP_STATE_CLOSED,
    [(int) tcp_state::TCP_STATE_CLOSED] = tcp_state::TCP_STATE_CLOSED,
};

/**
 * @brief Test if we should send a fin on a shutdown
 *
 * @param old_state Old TCP connection state
 * @return If true, we should send a fin, else false.
 */
static bool should_send_fin(tcp_state old_state)
{
    return old_state == tcp_state::TCP_STATE_ESTABLISHED ||
           old_state == tcp_state::TCP_STATE_CLOSE_WAIT ||
           old_state == tcp_state::TCP_STATE_SYN_RECEIVED;
}

int tcp_socket::shutdown(int how)
{
    scoped_hybrid_lock g{socket_lock, this};

    if (how & SHUTDOWN_WR)
    {
        // Shutdown the write end
        // Set the next state and send a FIN if necessary.
        const auto old_state = state;
        state = post_wr_shutdown_states[(int) state];

        if (should_send_fin(old_state))
        {
            send_fin();
            try_to_send();
        }
    }

    shutdown_state = how;

    // Lets find out needs to be woken up.
    // For now, only readers need to be unblocked.
    if (how & SHUTDOWN_RD)
    {
        wait_queue_wake_all(&rx_wq);
    }

    return 0;
}

void tcp_socket::close()
{
    if (__get_refcount() == 1)
    {
        // If we're the last reference to the socket, shut it down
        shutdown(SHUTDOWN_RDWR);

        // printk("close state %u refs %lu\n", state, __get_refcount());

        if (state == tcp_state::TCP_STATE_CLOSED)
        {
            // If we're closed, we're not getting TIME_WAIT'd, so just unref()
            unref();
        }

        // I genuinely don't know if there are leaks here.

        return;
    }

    unref();
}

/**
 * @brief Send a FIN segment to the remote host,
 *        to signal that we don't have more data to send.
 *
 * @return 0 on success, negative error codes
 */
int tcp_socket::send_fin()
{
    // TODO: Maybe separating the tcp header building into a function
    auto pbuf = make_refc<packetbuf>();

    if (!pbuf)
        return -ENOBUFS;

    if (!pbuf->allocate_space(MAX_TCP_HEADER_LENGTH))
        return -ENOBUFS;

    pbuf->reserve_headers(MAX_TCP_HEADER_LENGTH);
    tcp_header *tph = (tcp_header *) pbuf->push_header(sizeof(tcp_header));

    unsigned int flags = TCP_FLAG_ACK | TCP_FLAG_FIN;

    pbuf->transport_header = (unsigned char *) tph;

    memset(tph, 0, sizeof(tcp_header));

    auto &dest = daddr();

    auto data_off = TCP_MAKE_DATA_OFF(tcp_header_length_to_data_off(sizeof(tcp_header)));

    /* Assume the max window size as the window size, for now */
    tph->window_size = htons(our_window_size);
    tph->source_port = saddr().port;
    tph->sequence_number = htonl(snd_next);
    tph->data_offset_and_flags = htons(data_off | flags);
    tph->dest_port = dest.port;
    tph->urgent_pointer = 0;

    tph->ack_number = htonl(acknowledge_nr());

    auto &route = route_cache;
    auto nif = route.nif;

    bool need_csum = true;

    if (can_offload_csum(nif, pbuf.get()))
    {
        pbuf->csum_offset = &tph->checksum;
        pbuf->csum_start = (unsigned char *) tph;
        pbuf->needs_csum = 1;
        need_csum = false;
    }

    tph->checksum =
        call_based_on_inet(tcp_calculate_checksum, tph, static_cast<uint16_t>(sizeof(tcp_header)),
                           route.src_addr, route.dst_addr, need_csum);
    pending_out.append_packet(pbuf.release());

    // Note: Since we're shutting down the socket, there's no need to be careful wrt
    // cork code trying to fit more sendmsg() data into our fin packet.

    snd_next++; // For the FIN

    return 0;
}

expected<packetbuf *, int> tcp_socket::get_segment(int flags)
{
    int st = 0;
    packetbuf *buf = nullptr;

    do
    {
        if (st == -EINTR)
            return unexpected<int>{st};

        buf = get_rx_head();
        if (!buf && flags & MSG_DONTWAIT)
            return unexpected<int>{-EWOULDBLOCK};

        if (!buf && shutdown_state & SHUTDOWN_RD)
            return unexpected<int>{0};

        st = wait_for_segments();
    } while (!buf);

    return buf;
}

ssize_t tcp_socket::recvmsg(msghdr *msg, int flags)
{
    auto iovlen = iovec_count_length(msg->msg_iov, msg->msg_iovlen);
    if (iovlen < 0)
        return iovlen;

    scoped_hybrid_lock g{socket_lock, this};

    CONSUME_SOCK_ERR;

    auto st = get_segment(flags);
    if (st.has_error())
        return st.error();

    auto buf = st.value();

    ssize_t read = min(iovlen, (long) buf->length());
    ssize_t was_read = 0;
    ssize_t to_ret = read;

    if (iovlen < buf->length())
        msg->msg_flags = MSG_TRUNC;

    if (flags & MSG_TRUNC)
    {
        to_ret = buf->length();
    }

    const unsigned char *ptr = buf->data;

    if (msg->msg_name)
    {
        auto hdr = (tcp_header *) buf->transport_header;
        ip::copy_msgname_to_user(msg, buf, domain == AF_INET6, hdr->source_port);
    }

    auto tph = (tcp_header *) buf->transport_header;

    if (ntohs(tph->data_offset_and_flags) & TCP_FLAG_FIN)
    {
        // FIN packet! Let's return EOF and, if !MSG_PEEK, discard it.
        if (!(flags & MSG_PEEK))
        {
            list_remove(&buf->list_node);
            buf->unref();
        }

        return 0;
    }

    for (int i = 0; i < msg->msg_iovlen; i++)
    {
        auto iov = msg->msg_iov[i];
        auto to_copy = min((ssize_t) iov.iov_len, read - was_read);

        if (copy_to_user(iov.iov_base, ptr, to_copy) < 0)
        {
            return -EFAULT;
        }

        was_read += to_copy;

        ptr += to_copy;

        buf->data += to_copy;
    }

    msg->msg_controllen = 0;

    if (!(flags & MSG_PEEK))
    {
        if (buf->length() == 0)
        {
            list_remove(&buf->list_node);
            buf->unref();
        }
    }

#if 0
	printk("recv success %ld bytes\n", read);
	printk("iovlen %ld\n", iovlen);
#endif

    return to_ret;
}

short tcp_socket::poll(void *poll_file, short events)
{
    // TODO: Find this stuff out. It's kind of confusing and there doesn't seem
    // to be good documentation on this. Even the trusty UNIX Network Programming doesn't help...
    short avail_events = 0;

    scoped_hybrid_lock g2{socket_lock, this};

    if (state == tcp_state::TCP_STATE_CLOSED)
    {
        return POLLHUP;
    }

    if (state == tcp_state::TCP_STATE_LISTEN)
    {
        if (events & POLLIN)
        {
            if (accept_queue_len != 0)
            {
                avail_events |= POLLIN;
            }
            else
            {
                poll_wait_helper(poll_file, &accept_wq);
            }
        }

        return avail_events & events;
    }

    if (state == tcp_state::TCP_STATE_SYN_SENT)
    {
        avail_events &= ~POLLOUT;
        if (events & POLLOUT)
        {
            if (connection_pending)
                poll_wait_helper(poll_file, &conn_wq);
            else
                avail_events |= POLLOUT;
        }

        return avail_events & events;
    }

    if (events & POLLOUT)
    {
        if (!(shutdown_state & SHUTDOWN_WR))
            avail_events |= POLLOUT;
    }

    if (events & POLLIN)
    {
        if (has_data_available() || shutdown_state & SHUTDOWN_RD)
            avail_events |= POLLIN;
        else
            poll_wait_helper(poll_file, &rx_wq);
    }

    // printk("avail events: %u\n", avail_events);

    return avail_events & events;
}

int tcp_socket::getsockname(sockaddr *addr, socklen_t *len)
{
    if (!bound)
        return -EINVAL;

    copy_addr_to_sockaddr(src_addr, addr, len);

    return 0;
}

int tcp_socket::getpeername(sockaddr *addr, socklen_t *len)
{
    if (!connected)
        return -ENOTCONN;

    copy_addr_to_sockaddr(dest_addr, addr, len);

    return 0;
}

int tcp_socket::listen()
{
    if (state != tcp_state::TCP_STATE_CLOSED)
        return -EINVAL;

    if (!bound)
    {
        int st = get_proto_fam()->bind_any(this);

        if (st < 0)
            return -EADDRINUSE;
    }

    state = tcp_state::TCP_STATE_LISTEN;

    return 0;
}

tcp_socket::~tcp_socket()
{
    assert(state == tcp_state::TCP_STATE_CLOSED || state == tcp_state::TCP_STATE_TIME_WAIT);

    // Clear out the pending retransmitting packets
    list_for_every_safe (&pending_out_packets)
    {
        auto pkt = list_head_cpp<tcp_pending_out>::self_from_list_head(l);
        pkt->remove();
        pkt->unref();
    }

    // the inet cork should clear itself out in the destructor

    // unbinding should be done in inet_socket's destructor
}

socket *tcp_socket::accept(int flags)
{
    scoped_hybrid_lock g{socket_lock, this};
    tcp_socket *sock = nullptr;

    do
    {
        if (state != tcp_state::TCP_STATE_LISTEN)
            return errno = EINVAL, nullptr;

        if (accept_queue_len == 0 && flags & O_NONBLOCK)
            return errno = EWOULDBLOCK, nullptr;

        int st = wait_for_event_socklocked_interruptible(&accept_wq, accept_queue_len != 0);

        if (st < 0)
            return errno = -st, nullptr;

        assert(!list_is_empty(&accept_queue));

        sock = list_head_cpp<tcp_socket>::self_from_list_head(list_first_element(&accept_queue));

        list_remove(&sock->accept_node);
        accept_queue_len--;

    } while (sock == nullptr);

    return sock;
}

DEFINE_CPP_SOCKET_OPS(tcp_ops, tcp_socket);
