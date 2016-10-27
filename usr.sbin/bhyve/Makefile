#
# $FreeBSD$
#

PROG=	bhyve

DEBUG_FLAGS= -g -O0 

MAN=	bhyve.8

SRCS=	\
	atkbdc.c		\
	acpi.c			\
	bhyverun.c		\
	block_if.c		\
	bootrom.c		\
	consport.c		\
	dbgport.c		\
	fwctl.c			\
	inout.c			\
	ioapic.c		\
	mem.c			\
	mevent.c		\
	mptbl.c			\
	net_backends.c		\
	net_utils.c		\
	pci_ahci.c		\
	pci_emul.c		\
	pci_hostbridge.c	\
	pci_irq.c		\
	pci_lpc.c		\
	pci_passthru.c		\
	pci_ptnetmap_memdev.c	\
	pci_ptnetmap_netif.c	\
	pci_virtio_block.c	\
	pci_virtio_net.c	\
	pci_virtio_rnd.c	\
	pci_e82545.c		\
	pci_uart.c		\
	pm.c			\
	post.c			\
	rtc.c			\
	smbiostbl.c		\
	task_switch.c		\
	uart_emul.c		\
	virtio.c		\
	xmsr.c			\
	spinup_ap.c

.PATH:	${.CURDIR}/../../sys/amd64/vmm
SRCS+=	vmm_instruction_emul.c

DPADD=	${LIBVMMAPI} ${LIBMD} ${LIBUTIL} ${LIBPTHREAD}
LDADD=	-lvmmapi -lmd -lutil -lpthread

CFLAGS=-I/home/vmaffione/git/netmap/sys
CFLAGS+= -DWITH_NETMAP
CFLAGS+=-I../../sys/dev/e1000
CFLAGS+=-I../../sys/dev/mii

WARNS?=	2

.include <bsd.prog.mk>
