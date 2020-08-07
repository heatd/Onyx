net-y:= ethernet.o hostname.o ipv4/icmp.o ipv4/ipv4.o ipv4/ipv4_netkernel.o \
	ipv4/arp.o ipv6.o netif.o network.o socket.o udp.o packetbuf.o tcp.o loopback.o \
	checksum.o netkernel.o neighbour.o

obj-y+= $(patsubst %, kernel/net/%, $(net-y))
