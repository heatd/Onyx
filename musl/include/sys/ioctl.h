#ifndef	_SYS_IOCTL_H
#define	_SYS_IOCTL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <bits/alltypes.h>
#include <bits/ioctl.h>

#define N_TTY           0
#define N_SLIP          1
#define N_MOUSE         2
#define N_PPP           3
#define N_STRIP         4
#define N_AX25          5
#define N_X25           6
#define N_6PACK         7
#define N_MASC          8
#define N_R3964         9
#define N_PROFIBUS_FDL  10
#define N_IRDA          11
#define N_SMSBLOCK      12
#define N_HDLC          13
#define N_SYNC_PPP      14
#define N_HCI           15
#define N_GIGASET_M101  16
#define N_SLCAN         17
#define N_PPS           18
#define N_V253          19
#define N_CAIF          20
#define N_GSM0710       21
#define N_TI_WL         22
#define N_TRACESINK     23
#define N_TRACEROUTER   24
#define N_NCI           25
#define N_SPEAKUP       26
#define N_NULL          27

#define TIOCPKT_DATA       0
#define TIOCPKT_FLUSHREAD  1
#define TIOCPKT_FLUSHWRITE 2
#define TIOCPKT_STOP       4
#define TIOCPKT_START      8
#define TIOCPKT_NOSTOP    16
#define TIOCPKT_DOSTOP    32
#define TIOCPKT_IOCTL     64

#define TIOCSER_TEMT 1

struct winsize {
	unsigned short ws_row;
	unsigned short ws_col;
	unsigned short ws_xpixel;
	unsigned short ws_ypixel;
};

int ioctl (int, int, ...);

#ifdef __cplusplus
}
#endif
#endif
