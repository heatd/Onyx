/*
 * Copyright (c) 2024 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_UAPI_TCP_H
#define _ONYX_UAPI_TCP_H

#define TCP_NODELAY              1
#define TCP_MAXSEG               2
#define TCP_CORK                 3
#define TCP_KEEPIDLE             4
#define TCP_KEEPINTVL            5
#define TCP_KEEPCNT              6
#define TCP_SYNCNT               7
#define TCP_LINGER2              8
#define TCP_DEFER_ACCEPT         9
#define TCP_WINDOW_CLAMP         10
#define TCP_INFO                 11
#define TCP_QUICKACK             12
#define TCP_CONGESTION           13
#define TCP_MD5SIG               14
#define TCP_THIN_LINEAR_TIMEOUTS 16
#define TCP_THIN_DUPACK          17
#define TCP_USER_TIMEOUT         18
#define TCP_REPAIR               19
#define TCP_REPAIR_QUEUE         20
#define TCP_QUEUE_SEQ            21
#define TCP_REPAIR_OPTIONS       22
#define TCP_FASTOPEN             23
#define TCP_TIMESTAMP            24
#define TCP_NOTSENT_LOWAT        25
#define TCP_CC_INFO              26
#define TCP_SAVE_SYN             27
#define TCP_SAVED_SYN            28
#define TCP_REPAIR_WINDOW        29

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3
#define TCP_FIN_WAIT1   4
#define TCP_FIN_WAIT2   5
#define TCP_TIME_WAIT   6
#define TCP_CLOSE       7
#define TCP_CLOSE_WAIT  8
#define TCP_LAST_ACK    9
#define TCP_LISTEN      10
#define TCP_CLOSING     11

#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#define TCPOPT_EOL             0
#define TCPOPT_NOP             1
#define TCPOPT_MAXSEG          2
#define TCPOPT_WINDOW          3
#define TCPOPT_SACK_PERMITTED  4
#define TCPOPT_SACK            5
#define TCPOPT_TIMESTAMP       8
#define TCPOLEN_SACK_PERMITTED 2
#define TCPOLEN_WINDOW         3
#define TCPOLEN_MAXSEG         4
#define TCPOLEN_TIMESTAMP      10

#define SOL_TCP 6

#include <endian.h>
#include <stdint.h>

#include <onyx/types.h>

#include <uapi/socket.h>

typedef __u32 tcp_seq;

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

#ifndef __is_onyx_kernel

struct tcphdr
{
#ifdef _GNU_SOURCE
#ifdef __GNUC__
    __extension__
#endif
        union {
        struct
        {

            __u16 source;
            __u16 dest;
            __u32 seq;
            __u32 ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
            __u16 res1 : 4;
            __u16 doff : 4;
            __u16 fin : 1;
            __u16 syn : 1;
            __u16 rst : 1;
            __u16 psh : 1;
            __u16 ack : 1;
            __u16 urg : 1;
            __u16 res2 : 2;
#else
            __u16 doff : 4;
            __u16 res1 : 4;
            __u16 res2 : 2;
            __u16 urg : 1;
            __u16 ack : 1;
            __u16 psh : 1;
            __u16 rst : 1;
            __u16 syn : 1;
            __u16 fin : 1;
#endif
            __u16 window;
            __u16 check;
            __u16 urg_ptr;
        };
        struct
        {
#endif

            __u16 th_sport;
            __u16 th_dport;
            __u32 th_seq;
            __u32 th_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
            __u8 th_x2 : 4;
            __u8 th_off : 4;
#else
    __u8 th_off : 4;
    __u8 th_x2 : 4;
#endif
            __u8 th_flags;
            __u16 th_win;
            __u16 th_sum;
            __u16 th_urp;

#ifdef _GNU_SOURCE
        };
    };
#endif
};
#endif
#endif

#define TCPI_OPT_TIMESTAMPS 1
#define TCPI_OPT_SACK       2
#define TCPI_OPT_WSCALE     4
#define TCPI_OPT_ECN        8

#define TCP_CA_Open     0
#define TCP_CA_Disorder 1
#define TCP_CA_CWR      2
#define TCP_CA_Recovery 3
#define TCP_CA_Loss     4

struct tcp_info
{
    __u8 tcpi_state;
    __u8 tcpi_ca_state;
    __u8 tcpi_retransmits;
    __u8 tcpi_probes;
    __u8 tcpi_backoff;
    __u8 tcpi_options;
    __u8 tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
    __u8 tcpi_delivery_rate_app_limited : 1;
    __u32 tcpi_rto;
    __u32 tcpi_ato;
    __u32 tcpi_snd_mss;
    __u32 tcpi_rcv_mss;
    __u32 tcpi_unacked;
    __u32 tcpi_sacked;
    __u32 tcpi_lost;
    __u32 tcpi_retrans;
    __u32 tcpi_fackets;
    __u32 tcpi_last_data_sent;
    __u32 tcpi_last_ack_sent;
    __u32 tcpi_last_data_recv;
    __u32 tcpi_last_ack_recv;
    __u32 tcpi_pmtu;
    __u32 tcpi_rcv_ssthresh;
    __u32 tcpi_rtt;
    __u32 tcpi_rttvar;
    __u32 tcpi_snd_ssthresh;
    __u32 tcpi_snd_cwnd;
    __u32 tcpi_advmss;
    __u32 tcpi_reordering;
    __u32 tcpi_rcv_rtt;
    __u32 tcpi_rcv_space;
    __u32 tcpi_total_retrans;
    __u64 tcpi_pacing_rate;
    __u64 tcpi_max_pacing_rate;
    __u64 tcpi_bytes_acked;
    __u64 tcpi_bytes_received;
    __u32 tcpi_segs_out;
    __u32 tcpi_segs_in;
    __u32 tcpi_notsent_bytes;
    __u32 tcpi_min_rtt;
    __u32 tcpi_data_segs_in;
    __u32 tcpi_data_segs_out;
    __u64 tcpi_delivery_rate;
};

#define TCP_MD5SIG_MAXKEYLEN 80

struct tcp_md5sig
{
    struct sockaddr_storage tcpm_addr;
    __u16 __tcpm_pad1;
    __u16 tcpm_keylen;
    __u32 __tcpm_pad2;
    __u8 tcpm_key[TCP_MD5SIG_MAXKEYLEN];
};

struct tcp_repair_window
{
    __u32 snd_wl1;
    __u32 snd_wnd;
    __u32 max_window;
    __u32 rcv_wnd;
    __u32 rcv_wup;
};

#endif
