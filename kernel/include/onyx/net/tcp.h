/*
 * Copyright (c) 2020 - 2025 Pedro Falcato
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
    union {

        uint16_t data_offset_and_flags;
        struct
        {
            // clang-format off
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#else
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#endif
            // clang-format on
        };
    };
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

#define TCP_OPTION_END_OF_OPTIONS (0)
#define TCP_OPTION_NOP            (1)
#define TCP_OPTION_MSS            (2)
#define TCP_OPTION_WINDOW_SCALE   (3)
#define TCP_OPTION_SACK_PERMITTED (4)
#define TCP_OPTION_SACK           (5)
#define TCP_OPTION_TIMESTAMP      (8)

#define TCP_GET_DATA_OFF(off) (off >> TCP_DATA_OFFSET_SHIFT)

#ifdef __cplusplus

enum tcp_state
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

enum tcp_state_flags
{
    TCPF_STATE_LISTEN = 1 << 0,
    TCPF_STATE_SYN_SENT = 1 << 1,
    TCPF_STATE_SYN_RECEIVED = 1 << 2,
    TCPF_STATE_ESTABLISHED = 1 << 3,
    TCPF_STATE_FIN_WAIT_1 = 1 << 4,
    TCPF_STATE_FIN_WAIT_2 = 1 << 5,
    TCPF_STATE_CLOSE_WAIT = 1 << 6,
    TCPF_STATE_CLOSING = 1 << 7,
    TCPF_STATE_LAST_ACK = 1 << 8,
    TCPF_STATE_TIME_WAIT = 1 << 9,
    TCPF_STATE_CLOSED = 1 << 10
};

struct tcp_socket;

constexpr unsigned int tcp_retransmission_max = 15;

struct tcp_synack_options
{
    u16 mss;
    u8 snd_wnd_shift;
    u8 has_mss : 1, sacking : 1, has_window_scale : 1;
};

struct tcp_connreq
{
    struct spinlock tc_lock;
    struct inet_sock_address tc_src;
    struct inet_sock_address tc_dst;
    union {
        struct list_head tc_list_node;
        struct rcu_head tc_rcu_head;
    };

    struct list_head tc_hashtab_node;
    struct tcp_socket *tc_sock;
    struct packetbuf *tc_syndata;
    struct inet_route tc_route;
    struct tcp_synack_options tc_opts;
    u32 tc_our_mss;
    u32 tc_rcv_nxt;
    u32 tc_iss;
    int tc_domain;
    int tc_dead : 1;
};

struct tcp_sack_range
{
    unsigned int start, end;
};

struct tcp_socket : public inet_socket
{
    enum tcp_state state;
    int type;
    wait_queue conn_wq;
    u16 send_mss, rcv_mss, mss;
    u32 snd_wnd, snd_wnd_shift;
    u32 rcv_wnd, rcv_wnd_shift;

    /* First byte that's unacknowledged (everything before it has been ack'd) */
    u32 snd_una;
    /* Next allowed sequence number (everything before it has been ack'd or is in-transit) */
    u32 snd_next;
    /* First unseen sequence number */
    u32 rcv_next;

    /* Segment sequence number used for last window update */
    u32 snd_wl1;
    /* Segment ack number used for last window update */
    u32 snd_wl2;

    bool nagle_enabled : 1;
    bool retrans_active : 1 {0};
    int retrans_pending : 1 {0};
    int delack_active : 1 {0};
    int delack_pending : 1 {0};
    int sacking : 1, sack_needs_send : 1;

    int retransmit_try{0};
    struct clockevent retransmit_timer;
    struct clockevent delack_timer;
    struct list_head output_queue;
    struct list_head on_wire_queue;
    struct list_head read_queue;

    struct bst_root out_of_order_tree;

    /* RFC2018 limits sacks to 4 ((40 bytes of options / 8) - 2). We retransmit each sack at least 4
     * times. */
    struct tcp_sack_range sacks[4];
    unsigned int nr_sacks;
    int mss_for_ack;

    struct list_head accept_queue;
    struct list_head conn_queue;
    int connqueue_len;
};

constexpr inline uint16_t tcp_header_length_to_data_off(uint16_t len)
{
    return len >> 2;
}

constexpr inline uint16_t tcp_header_data_off_to_length(uint16_t len)
{
    return len << 2;
}

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
    TCP_DROP_SYN_BAD_ACK,
    TCP_DROP_NO_SYN,
    TCP_DROP_UNCROMULENT1,
    TCP_DROP_UNCROMULENT2,
    TCP_DROP_BAD_SYN,
    TCP_DROP_OUT_OF_ORDER,
    TCP_DROP_OOO_DUP,
    TCP_DROP_RST_ON_LISTEN,
};

static inline bool tcp_state_is_fl(struct tcp_socket *sock, int flags)
{
    return (1 << sock->state) & flags;
}

void tcp_set_state(struct tcp_socket *sock, enum tcp_state state);

#endif

struct socket *tcp_create_socket(int type);
int tcp_handle_packet(const inet_route &route, packetbuf *buf);
int tcp6_handle_packet(const inet_route &route, packetbuf *buf);
extern socket_table tcp_table;
extern const inet_proto tcp_proto;
bool validate_tcp_packet(const tcp_header *header, size_t size);
int tcp_input(struct tcp_socket *sock, struct packetbuf *pbf);
void tcp_stop_retransmit(struct tcp_socket *sock);

/*
 * The next routines deal with comparing 32 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 */

static inline bool before(__u32 seq1, __u32 seq2)
{
    return (__s32) (seq1 - seq2) < 0;
}
#define after(seq2, seq1) before(seq1, seq2)

/* is s2<=s1<=s3 ? */
static inline bool between(__u32 seq1, __u32 seq2, __u32 seq3)
{
    return seq3 - seq2 >= seq1 - seq2;
}

int tcp_send_ack(struct tcp_socket *sock);
int tcp_output(struct tcp_socket *sock);
int tcp_send_synack(struct tcp_connreq *conn);
void __tcp_send_rst(struct packetbuf *pbf, u32 seq, u32 ack_nr, int ack);
void tcp_send_rst(struct tcp_socket *sock, struct packetbuf *pbf);
void tcp_done_error(struct tcp_socket *sock, int err);
void tcp_time_wait(struct tcp_socket *sock);

#endif
