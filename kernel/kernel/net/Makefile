net-y:= arp.o ethernet.o hostname.o icmp.o ipv4.o ipv6.o netif.o network.o socket.o \
	udp.o packetbuf.o tcp.o loopback.o checksum.o

obj-y+= $(patsubst %, kernel/net/%, $(net-y))
