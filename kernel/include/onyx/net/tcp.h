/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_NET_TCP_H
#define _ONYX_NET_TCP_H

#include <stddef.h>
#include <stdint.h>

#include <onyx/mutex.h>
#include <onyx/net/ip.h>
#include <onyx/net/socket.h>
#include <onyx/packetbuf.h>
#include <onyx/refcount.h>
#include <onyx/scoped_lock.h>
#include <onyx/semaphore.h>
#include <onyx/vector.h>
#include <onyx/wait_queue.h>

#include <onyx/memory.hpp>
#include <onyx/slice.hpp>

struct tcp_header
{
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint16_t data_offset_and_flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
    uint8_t options[];
} __attribute__((packed));

#define MAX_TCP_HEADER_LENGTH (PACKET_MAX_HEAD_LENGTH + 60)

#define TCP_FLAG_FIN          (uint16_t)(1 << 0)
#define TCP_FLAG_SYN          (uint16_t)(1 << 1)
#define TCP_FLAG_RST          (uint16_t)(1 << 2)
#define TCP_FLAG_PSH          (uint16_t)(1 << 3)
#define TCP_FLAG_ACK          (uint16_t)(1 << 4)
#define TCP_FLAG_URG          (uint16_t)(1 << 5)
#define TCP_FLAG_ECE          (uint16_t)(1 << 6)
#define TCP_FLAG_CWR          (uint16_t)(1 << 7)
#define TCP_FLAG_NS           (uint16_t)(1 << 8)
#define TCP_DATA_OFFSET_SHIFT (12)
#define TCP_DATA_OFFSET_MASK  (0xf)

#define TCP_HEADER_MAX_SIZE 60

#define TCP_OPTION_END_OF_OPTIONS   (0)
#define TCP_OPTION_NOP              (1)
#define TCP_OPTION_MSS              (2)
#define TCP_OPTION_WINDOW_SCALE     (3)
#define TCP_OPTION_SACK_PERGPLv2TED (4)
#define TCP_OPTION_SACK             (5)
#define TCP_OPTION_TIMESTAMP        (8)

#define TCP_GET_DATA_OFF(off) (off >> TCP_DATA_OFFSET_SHIFT)

#ifdef __cplusplus

enum class tcp_state
{
    TCP_STATE_LISTEN = 0,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
    TCP_STATE_CLOSED
};

class tcp_ack
{
    /* Same as below */
public:
    tcp_header *packet;
    uint16_t length;

public:
    list_head list_node;

    tcp_ack(tcp_header *packet, uint16_t length) : packet(packet), length(length)
    {
    }

    ~tcp_ack()
    {
        free(packet);
    }

    void append(list_head *head)
    {
        list_add(&list_node, head);
    }

    void remove()
    {
        list_remove(&list_node);
    }

    tcp_header *get_packet() const
    {
        return packet;
    }

    uint16_t get_length() const
    {
        return length;
    }
};

class tcp_option
{
public:
    /* Lets use a static buffer to simplify things, using the length of SACK as the largest (since
     * it is atm). This won't need to be future proof since we can progressively update it as time
     * goes on, since we won't send options we're not aware of.
     */

    static constexpr uint8_t largest_length = (34 - 2);
    uint8_t kind;
    uint8_t length;
    union {
        uint16_t mss;
        uint8_t window_scale_shift;
        uint8_t _data[largest_length];
    } data;
    /* If it was allocated dynamically, the tcp_packet dtor needs to delete it */
    uint8_t dynamic;

    struct list_head list_node;

    tcp_option(uint8_t kind, uint8_t length) : kind{kind}, length{length}, dynamic{0}, list_node{}
    {
    }

    ~tcp_option()
    {
    }
};

class tcp_socket;

#define TCP_PACKET_FLAG_ON_STACK         (1 << 0)
#define TCP_PACKET_FLAG_WANTS_ACK_HEADER (1 << 1)

#include <onyx/cpu.h>

class tcp_packet : public refcountable
{

    /* We have to use public here so offsetof isn't UB */
public:
    cul::slice<const uint8_t> payload;
    tcp_socket *socket;
    ref_guard<packetbuf> buf;
    struct list_head option_list;
    uint16_t flags;
    const inet_sock_address &saddr;
    /* Ideas at 4.am: Have a struct that stores both a list_head and a pointer to the
     * original class, and make code use that instead of container_of. This should work
     * properly for every kind of class, and would avoid having to construct list_node<T>'s.
     */
    list_head_cpp<tcp_packet> pending_packet_list_node;
    bool acked;
    wait_queue ack_wq;
    uint16_t packet_flags;
    tcp_header *response_header;
    uint32_t starting_seq_number;

    void delete_options()
    {
        list_for_every_safe (&option_list)
        {
            tcp_option *opt = container_of(l, tcp_option, list_node);

            list_remove(l);
            if (opt->dynamic)
                delete opt;
        }
    }

    void put_options(char *opts);

    tcp_packet(cul::slice<const uint8_t> data, tcp_socket *socket, uint16_t flags,
               const inet_sock_address &in)
        : refcountable(), payload(data), socket(socket), buf{}, option_list{}, flags(flags),
          saddr(in), pending_packet_list_node{this}, acked{false}, ack_wq{}, packet_flags{},
          response_header{}, starting_seq_number{}
    {
        INIT_LIST_HEAD(&option_list);
        init_wait_queue_head(&ack_wq);
    }

    void wait_for_single_ref() const
    {
        /* Busy-loop waiting for the refc to drop - this shouldn't take long */
        while (__refcount.load() != 1)
            cpu_relax();
    }

    ~tcp_packet()
    {

        /* If we're on stack we want to make sure we're the only reference to this */
        if (packet_flags & TCP_PACKET_FLAG_ON_STACK)
            wait_for_single_ref();

        delete_options();
    }

    uint16_t options_length() const;
    void set_packet_flags(uint16_t flags)
    {
        this->packet_flags = flags;
    }

    bool ack_for_packet(uint32_t last_ack, uint32_t this_ack)
    {
        auto ack_length = static_cast<uint32_t>(payload.size_bytes());
        if (flags & TCP_FLAG_SYN)
            ack_length++;

        if (starting_seq_number >= last_ack && this_ack >= starting_seq_number + ack_length)
            return true;

        return false;
    }

    ref_guard<packetbuf> result();

    constexpr bool should_wait_for_ack()
    {
        /* TODO: Add all the other cases */
        if (flags == TCP_FLAG_ACK && payload.size_bytes() == 0)
            return false;
        return true;
    }

    int wait_for_ack();
    int wait_for_ack_timeout(hrtime_t timeout);

    tcp_socket *get_socket()
    {
        return socket;
    }

    void append_option(tcp_option *opt)
    {
        list_add(&opt->list_node, &option_list);
    }
};

constexpr unsigned int tcp_retransmission_max = 15;

struct tcp_pending_out;

struct tcp_connection_req
{
    inet_sock_address from;
    inet_sock_address to;
    uint16_t mss;
    uint32_t ack_number;
    uint32_t seq_number;
    uint32_t window_size;
    uint8_t window_shift;
    struct list_head list_node;
    inet_route route;
    int domain;
    ref_guard<tcp_pending_out> syn_ack_pending;

    static constexpr uint16_t default_mss = 536;

    struct list_head received_data;

    tcp_connection_req() = delete;
    CLASS_DISALLOW_COPY(tcp_connection_req);
    CLASS_DISALLOW_MOVE(tcp_connection_req);

    tcp_connection_req(inet_route &&route, int domain)
        : mss{default_mss}, route{cul::move(route)}, domain{domain}
    {
        INIT_LIST_HEAD(&received_data);
    }

    /**
     * @brief Parse an incoming SYN
     *
     * @param tcphdr Pointer to the tcp header
     * @return True if valid, else false
     */
    bool parse_syn(const tcp_header *tcphdr);

    /**
     * @brief Send a SYN-ACK packet
     *
     * @return 0 on success, negative error codes
     */
    int send_synack();

    /**
     * @brief Sends a packetbuf
     *
     * @param buf Packetbuf to send
     * @param noack True if no ack is needed
     * @return 0 on success,negative error codes
     */
    int sendpbuf(ref_guard<packetbuf> buf, bool noack);
};

class tcp_socket : public inet_socket
{
private:
    enum tcp_state state;
    int type;
    struct list_head pending_out_packets;
    wait_queue tcp_ack_wq;
    wait_queue conn_wq;
    uint16_t mss;
    uint32_t window_size;
    uint8_t window_size_shift;
    uint32_t our_window_size;
    uint8_t our_window_shift;

    /* First byte that's unacknowledged (everything before it has been ack'd) */
    u32 snd_una;
    /* Next allowed sequence number (everything before it has been ack'd or is in-transit) */
    u32 snd_next;
    /* First unseen sequence number */
    u32 rcv_next;
    bool connection_pending;
    inet_cork pending_out;

    bool nagle_enabled : 1;
    bool retrans_active : 1 {0};
    int retrans_pending : 1 {0};

    int retransmit_try{0};
    struct clockevent retransmit_timer;
    // Done as a pointer so we save some space
    unique_ptr<clockevent> time_wait_timer;

    // Note: Both of these queues are bounded by the backlog

    // The syn queue holds incoming connection requests and is matched against the ACK
    // of the TCP handshake.
    int syn_queue_len;
    struct list_head syn_queue;
    // The accept queue holds complete sockets ready to be accepted
    int accept_queue_len;
    struct list_head accept_queue;
    wait_queue accept_wq;

    list_head_cpp<tcp_socket> accept_node;

    int start_handshake(netif *nif, int flags);

    /**
     * @brief Finish a connection
     *
     */
    void finish_conn();

    bool parse_options(tcp_header *packet);
    ssize_t get_max_payload_len(uint16_t tcp_header_len);

    void append_pending_out(tcp_pending_out *packet);
    void remove_pending_out(tcp_pending_out *packet);

    packetbuf *get_rx_head()
    {
        if (list_is_empty(&rx_packet_list))
            return nullptr;

        return list_head_cpp<packetbuf>::self_from_list_head(list_first_element(&rx_packet_list));
    }

    bool has_data_available()
    {
        return !list_is_empty(&rx_packet_list);
    }

    expected<packetbuf *, int> get_segment(int flags);

    int wait_for_segments()
    {
        return wait_for_event_socklocked_interruptible(&rx_wq, !list_is_empty(&rx_packet_list));
    }

    /**
     * @brief Send a FIN segment to the remote host,
     *        to signal that we don't have more data to send.
     *
     * @return 0 on success, negative error codes
     */
    int send_fin();

    /**
     * @brief Reset the connection
     *
     */
    void reset();

    /**
     * @brief Send a reset segment
     *
     */
    void send_reset();

    /**
     * @brief Handle an incoming FIN packet
     *
     * @param buf Packetbuf we got
     */
    void handle_fin(packetbuf *buf);

    /**
     * @brief Send an ACK segment
     *
     */
    void send_ack();

    /**
     * @brief Put the socket in a TIME_WAIT state
     *
     */
    void set_time_wait();

    /**
     * @brief Makes an established connection from a connection request
     *
     * @param req Pointer to the tcp connection request
     * @return 0 on success, negative error codes
     */
    int make_connection_from(const tcp_connection_req *req);

    /**
     * @brief Append a packetbuf packet to the backlog
     *
     * @param buf packetbuf
     */
    void append_backlog(packetbuf *buf);

    /**
     * @brief Prepare segment for sending
     *
     * @param buf Packetbuf
     */
    void prepare_segment(packetbuf *buf);

    packetbuf *clone_for_send(packetbuf *buf);

    void start_retransmit();

    void start_retransmit_timer(hrtime_t timeout);

    void retransmit_segments();

    void stop_retransmit();

    int append_data(const iovec *vec, size_t vec_len, size_t mss);
    int alloc_and_append(const iovec *vec, size_t vec_len, size_t mss, size_t skip_first);

public:
    struct spinlock pending_out_lock;

    struct packet_handling_data
    {
        packetbuf *buffer;
        tcp_header *header;
        uint16_t tcp_segment_size;
        sockaddr_in_both *src_addr;
        int domain;
        const inet_route &route;

        packet_handling_data(packetbuf *buffer, tcp_header *header, uint16_t segm_size,
                             sockaddr_in_both *b, int domain, const inet_route &r)
            : buffer{buffer}, header(header), tcp_segment_size(segm_size),
              src_addr(b), domain{domain}, route{r}
        {
        }
    };

    /**
     * @brief Handle packet recv on SYN_SENT
     *
     * @param data Packet handling data
     * @return 0 on success, negative error codes
     */
    int do_receive_syn_sent(const packet_handling_data &data);

    /**
     * @brief Handle packet recv on ESTABLISHED
     *
     * @param data Packet handling data
     * @return 0 on success, negative error codes
     */
    int do_established_rcv(const packet_handling_data &data);

    /**
     * @brief Handle packet recv on LISTEN
     *
     * @param data Packet handling data
     * @return 0 on success, negative error codes
     */
    int do_listen_rcv(const packet_handling_data &data);

    /**
     * @brief Handle a SYN packet
     *
     * @param data Packet handling data
     * @return 0 on success, negative error codes
     */
    int incoming_syn(const packet_handling_data &data);

    /**
     * @brief Accept a connection following an ACK
     *
     * @param data Packet handling data
     * @return 0 on success, negative error codes
     */
    int handle_synack_ack(const packet_handling_data &data);

    /**
     * @brief Accept a connection
     *
     * @param req TCP connection request to accept and make into a socket
     * @param data Packet handling data
     * @return 0 on success, negative error codes
     */
    int accept_connection(tcp_connection_req *req, const packet_handling_data &data);

    int handle_packet(const packet_handling_data &data);

    /**
     * @brief Handle an incoming TCP segment
     *
     * @param data Packet handling data
     * @return 0 on sucesss, negative error codes
     */
    int handle_segment(const packet_handling_data &data);

    friend class tcp_packet;

    static constexpr uint16_t default_mss = 536;
    static constexpr uint16_t default_window_size_shift = 0;

    // FIXME: Nagle's algorithm was disabled, as it isn't stable.
    tcp_socket()
        : inet_socket{}, state(tcp_state::TCP_STATE_CLOSED),
          type(SOCK_STREAM), pending_out_packets{}, tcp_ack_wq{}, conn_wq{}, mss{default_mss},
          window_size{0}, window_size_shift{default_window_size_shift}, our_window_size{UINT16_MAX},
          our_window_shift{default_window_size_shift}, snd_una{0}, snd_next{0}, rcv_next{0},
          connection_pending{}, pending_out{SOCK_STREAM}, nagle_enabled{true}, time_wait_timer{},
          syn_queue_len{}, syn_queue{}, accept_queue_len{}, accept_queue{}, accept_node{this},
          pending_out_lock{}
    {
        init_wait_queue_head(&conn_wq);
        init_wait_queue_head(&tcp_ack_wq);
        INIT_LIST_HEAD(&pending_out_packets);
        INIT_LIST_HEAD(&syn_queue);
        INIT_LIST_HEAD(&accept_queue);
        init_wait_queue_head(&accept_wq);
    }

    bool can_send() const
    {
        return state == tcp_state::TCP_STATE_ESTABLISHED ||
               state == tcp_state::TCP_STATE_CLOSE_WAIT;
    }

    ~tcp_socket();

    const inet_sock_address &saddr()
    {
        return src_addr;
    }
    const inet_sock_address &daddr()
    {
        return dest_addr;
    }

    uint32_t other_window() const
    {
        return window_size;
    }

    int bind(struct sockaddr *addr, socklen_t addrlen) override;
    int connect(struct sockaddr *addr, socklen_t addrlen, int flags) override;

    int start_connection(int flags);

    ssize_t sendmsg(const msghdr *msg, int flags) override;

    u32 &sequence_nr()
    {
        return snd_next;
    }

    uint32_t acknowledge_nr()
    {
        return rcv_next;
    }

    ssize_t queue_data(iovec *vec, int vlen, size_t count);

    int setsockopt(int level, int opt, const void *optval, socklen_t optlen) override;
    int getsockopt(int level, int opt, void *optval, socklen_t *optlen) override;
    int shutdown(int how) override;
    void close() override;
    ssize_t recvmsg(msghdr *msg, int flags) override;
    short poll(void *poll_file, short events) override;

    int getsockname(sockaddr *addr, socklen_t *len) override;
    int getpeername(sockaddr *addr, socklen_t *len) override;
    socket *accept(int flags) override;

    int listen() override;

    /**
     * @brief Sends a packetbuf
     *
     * @param buf Packetbuf to send
     * @param noack True if no ack is needed
     * @return Expected of a ref_guard to a tcp_pending_out, or a negative error code
     */
    expected<ref_guard<tcp_pending_out>, int> sendpbuf(packetbuf *buf, bool noack = false);

    /**
     * @brief Does acknowledgement of packets
     *
     * @param buf Packetbuf of the ack packet we got
     */
    int do_ack(packetbuf *buf);

    /**
     * @brief Fail a connection attempt
     *
     * @param error Error it failed with
     */
    void conn_fail(int error);

    /**
     * @brief Try to send data
     *
     * @return 0 on success, negative error codes
     */
    int try_to_send();

    /**
     * @brief Checks if we can send a packet according to nagle's algorithm
     *
     * @param buf Packetbuf to check
     * @return True if possible, else false.
     */
    bool nagle_can_send(packetbuf *buf);

    /**
     * @brief Sends a data segment
     *
     * @param buf Packetbuf to send
     * @return 0 on success, negative error codes
     */
    int send_segment(packetbuf *buf);

    /**
     * @brief Handle TCP socket backlog (pending segments)
     *
     */
    void handle_backlog() override;

    void do_retransmit();
};

constexpr inline uint16_t tcp_header_length_to_data_off(uint16_t len)
{
    return len >> 2;
}

constexpr inline uint16_t tcp_header_data_off_to_length(uint16_t len)
{
    return len << 2;
}

/**
 * @brief Describes a packet that is pending out
 *
 */
struct tcp_pending_out : public refcountable
{
    ref_guard<packetbuf> buf;
    list_head_cpp<tcp_pending_out> node;
    unsigned int transmission_try{};
    union {
        tcp_socket *sock;
        tcp_connection_req *req;
    };

    bool acked{};
    bool reset{};
    wait_queue wq;
    void (*fail)(tcp_pending_out *out);
    void (*done_callback)(tcp_pending_out *out);

    tcp_pending_out(tcp_socket *s) : refcountable(), node{this}, sock{s}, fail{}, done_callback{}
    {
        init_wait_queue_head(&wq);
    }

    tcp_pending_out(tcp_connection_req *r)
        : refcountable(), node{this}, req{r}, fail{}, done_callback{}
    {
        init_wait_queue_head(&wq);
    }

    /**
     * @brief Tests if we need to wait longer for the pending out
     *
     * @return true
     * @return false
     */
    bool done() const
    {
        return reset || acked;
    }

    /**
     * @brief Wait for a packet's ack
     *
     * @return 0 on success, -EINTR if interrupted, -ETIMEDOUT if timed out, -ECONNRESET if the
     * connection was reset
     */
    int wait()
    {
        int st = wait_for_event_socklocked_interruptible_2(&wq, done(), sock);

        if (st == -EINTR)
            remove();

        return st == -EINTR
                   ? st
                   : (transmission_try == tcp_retransmission_max ? -ETIMEDOUT
                                                                 : (reset ? -ECONNRESET : 0));
    }

    /**
     * @brief Remove the tcp_pending_out from the list, and drop our ref
     * Note: socket lock held
     *
     */
    void remove()
    {
        list_remove(&node);
    }

    /**
     * @brief Test if an ack was for this packet
     *
     * @param last_ack Last ack we got
     * @param this_ack This ack
     * @return True if this ack acks this packet, else false
     */
    bool ack_for_packet(uint32_t last_ack, uint32_t this_ack) const
    {
        const auto tcphdr = (const tcp_header *) buf->transport_header;
        return ntohl(tcphdr->sequence_number) < this_ack;
    }

    /**
     * @brief Do the ACK
     * @param new_una New snd_una
     *
     * @return True if ack completely covers the packet (i.e can be freed)
     */
    bool do_ack(u32 new_una);
};

enum tcp_drop_reason
{
    TCP_ACCEPTED = 0,
    TCP_DROP_NOSOCK,
    TCP_DROP_BAD_PACKET,
    TCP_DROP_CSUM_ERR,
    TCP_DROP_NOACK,
    TCP_DROP_GENERIC,
    TCP_DROP_ACK_UNSENT,
    TCP_DROP_ACK_DUP,
};

#endif

struct socket *tcp_create_socket(int type);
int tcp_init_netif(struct netif *netif);
int tcp_handle_packet(const inet_route &route, packetbuf *buf);
int tcp6_handle_packet(const inet_route &route, packetbuf *buf);

#endif
