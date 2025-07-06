/*
 * Copyright (c) 2023 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_IOCTLS_H
#define _UAPI_IOCTLS_H

#include <uapi/ioctl.h>

#define TCGETS       0x5401
#define TCSETS       0x5402
#define TCSETSW      0x5403
#define TCSETSF      0x5404
#define TCGETA       0x5405
#define TCSETA       0x5406
#define TCSETAW      0x5407
#define TCSETAF      0x5408
#define TCSBRK       0x5409
#define TCXONC       0x540A
#define TCFLSH       0x540B
#define TIOCEXCL     0x540C
#define TIOCNXCL     0x540D
#define TIOCSCTTY    0x540E
#define TIOCGPGRP    0x540F
#define TIOCSPGRP    0x5410
#define TIOCOUTQ     0x5411
#define TIOCSTI      0x5412
#define TIOCGWINSZ   0x5413
#define TIOCSWINSZ   0x5414
#define TIOCMGET     0x5415
#define TIOCMBIS     0x5416
#define TIOCMBIC     0x5417
#define TIOCMSET     0x5418
#define TIOCGSOFTCAR 0x5419
#define TIOCSSOFTCAR 0x541A
#define FIONREAD     0x541B
#define TIOCINQ      FIONREAD
#define TIOCLINUX    0x541C
#define TIOCCONS     0x541D
#define TIOCGSERIAL  0x541E
#define TIOCSSERIAL  0x541F
#define TIOCPKT      0x5420
#define FIONBIO      0x5421
#define TIOCNOTTY    0x5422
#define TIOCSETD     0x5423
#define TIOCGETD     0x5424
#define TCSBRKP      0x5425
#define TIOCSBRK     0x5427
#define TIOCCBRK     0x5428
#define TIOCGSID     0x5429
#define TIOCGRS485   0x542E
#define TIOCSRS485   0x542F
#define TIOCGPTN     0x80045430
#define TIOCSPTLCK   0x40045431
#define TIOCGDEV     0x80045432
#define TCGETX       0x5432
#define TCSETX       0x5433
#define TCSETXF      0x5434
#define TCSETXW      0x5435
#define TIOCSIG      0x40045436
#define TIOCVHANGUP  0x5437
#define TIOCGPKT     0x80045438
#define TIOCGPTLCK   0x80045439
#define TIOCGEXCL    0x80045440

#define FIONCLEX        0x5450
#define FIOCLEX         0x5451
#define FIOASYNC        0x5452
#define FIGETBSZ        _IO(0, 2)
#define TIOCSERCONFIG   0x5453
#define TIOCSERGWILD    0x5454
#define TIOCSERSWILD    0x5455
#define TIOCGLCKTRMIOS  0x5456
#define TIOCSLCKTRMIOS  0x5457
#define TIOCSERGSTRUCT  0x5458
#define TIOCSERGETLSR   0x5459
#define TIOCSERGETMULTI 0x545A
#define TIOCSERSETMULTI 0x545B
#define TIOCMIWAIT      0x545C
#define TIOCGICOUNT     0x545D
#define FIOQSIZE        0x5460

#define TIOONYXCTL 0x5461

#define SIOSETINET4     0x9000
#define SIOADDINET6ADDR 0x9001
#define SIOGETINET4     0x9002
#define SIOGETINET6     0x9003
#define SIOGETMAC       0x9004
#define SIOGETIFNAME    0x9005
#define SIOGETINDEX     0x9006

#define SIOCGIFNAME  0x8910
#define SIOCGIFCONF  0x8912
#define SIOCGIFFLAGS 0x8913
#define SIOCSIFFLAGS 0x8914
#define SIOCGIFADDR  0x8915
#define SIOCSIFADDR  0x8916
#define SIOCGIFNETMASK     0x891b
#define SIOCSIFNETMASK     0x891c
#define SIOCGIFMTU         0x8921
#define SIOCSIFMTU         0x8922
#define SIOCSIFHWADDR      0x8924
#define SIOCGIFHWADDR      0x8927

struct winsize
{
    unsigned short ws_row;
    unsigned short ws_col;
    unsigned short ws_xpixel;
    unsigned short ws_ypixel;
};

#define TIOCM_LE   0x001
#define TIOCM_DTR  0x002
#define TIOCM_RTS  0x004
#define TIOCM_ST   0x008
#define TIOCM_SR   0x010
#define TIOCM_CTS  0x020
#define TIOCM_CAR  0x040
#define TIOCM_RNG  0x080
#define TIOCM_DSR  0x100
#define TIOCM_CD   TIOCM_CAR
#define TIOCM_RI   TIOCM_RNG
#define TIOCM_OUT1 0x2000
#define TIOCM_OUT2 0x4000
#define TIOCM_LOOP 0x8000

#define N_TTY          0
#define N_SLIP         1
#define N_MOUSE        2
#define N_PPP          3
#define N_STRIP        4
#define N_AX25         5
#define N_X25          6
#define N_6PACK        7
#define N_MASC         8
#define N_R3964        9
#define N_PROFIBUS_FDL 10
#define N_IRDA         11
#define N_SMSBLOCK     12
#define N_HDLC         13
#define N_SYNC_PPP     14
#define N_HCI          15

#ifdef __is_onyx_kernel
#include <uapi/netinet.h>

struct if_config_inet
{
    struct in_addr address;
    struct in_addr router;
    struct in_addr subnet;
};

#ifndef IF_INET6_DEFINED

struct if_inet6_addr
{
    struct in6_addr address;
    uint16_t flags;
    uint8_t prefix_len;
};

#define INET6_ADDR_LOCAL  (1 << 0)
#define INET6_ADDR_GLOBAL (1 << 1)

#define IF_INET6_DEFINED

#endif
#endif

#endif
