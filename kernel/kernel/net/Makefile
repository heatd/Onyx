net-$(CONFIG_NET):= ethernet.o netif.o netkernel.o ipv4/icmp.o ipv4/ipv4.o ipv4/ipv4_netkernel.o \
	ipv4/arp.o ipv6/ipv6.o udp.o packetbuf.o tcp.o loopback.o \
	checksum.o neighbour.o inet.o ipv6/ndp.o ipv6/icmpv6.o ipv6/ipv6_netkernel.o \
	socket_table.o inet_cork.o unix.o tcp_input.o netlink.o rtnetlink.o

net-y:=$(net-y) network.o socket.o hostname.o

obj-y+= $(patsubst %, kernel/net/%, $(net-y))
