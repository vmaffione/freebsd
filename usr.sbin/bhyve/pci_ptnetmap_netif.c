/*
 * Copyright (C) 2016 Vincenzo Maffione
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <net/if.h>	/* IFNAMSIZ */
#include <net/netmap.h>
#include <dev/netmap/netmap_virt.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "pci_emul.h"
#include "net_backends.h"

#ifndef PTNET_CSB_ALLOC
#error "Hypervisor-allocated CSB not supported"
#endif


struct ptnet_softc {
	struct pci_devinst	*pi;

	struct net_backend	*be;
	struct ptnetmap_state	*ptbe;

	unsigned int		num_rings;
	uint32_t		ioregs[PTNET_IO_END >> 2];
	void			*csb;
};

static int
ptnet_get_netmap_if(struct ptnet_softc *sc)
{
	unsigned int num_rings;
	struct netmap_if_info nif;
	int ret;

	ret = ptnetmap_get_netmap_if(sc->ptbe, &nif);
	if (ret) {
		return ret;
	}

	sc->ioregs[PTNET_IO_NIFP_OFS >> 2] = nif.nifp_offset;
	sc->ioregs[PTNET_IO_NUM_TX_RINGS >> 2] = nif.num_tx_rings;
	sc->ioregs[PTNET_IO_NUM_RX_RINGS >> 2] = nif.num_rx_rings;
	sc->ioregs[PTNET_IO_NUM_TX_SLOTS >> 2] = nif.num_tx_slots;
	sc->ioregs[PTNET_IO_NUM_RX_SLOTS >> 2] = nif.num_rx_slots;

	num_rings = sc->ioregs[PTNET_IO_NUM_TX_RINGS >> 2] +
		    sc->ioregs[PTNET_IO_NUM_RX_RINGS >> 2];
	if (sc->num_rings && num_rings && sc->num_rings != num_rings) {
		fprintf(stderr, "Number of rings changed: not supported\n");
		return EINVAL;
	}
	sc->num_rings = num_rings;

	return 0;
}

static uint64_t
ptnet_bar_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
	       int baridx, uint64_t offset, int size)
{
	struct ptnet_softc *sc = pi->pi_arg;

	if (sc == NULL)
		return 0;

	offset = offset & PTNET_IO_MASK;

	if (baridx == PTNETMAP_IO_PCI_BAR && offset < PTNET_IO_END) {
		switch (offset) {
		case PTNET_IO_NIFP_OFS:
		case PTNET_IO_NUM_TX_RINGS:
		case PTNET_IO_NUM_RX_RINGS:
		case PTNET_IO_NUM_TX_SLOTS:
		case PTNET_IO_NUM_RX_SLOTS:
			/* Fill in device registers with information about
			 * nifp_offset, num_*x_rings, and num_*x_slots. */
			ptnet_get_netmap_if(sc);

		default:
			return sc->ioregs[offset >> 2];
		}
	}

	fprintf(stderr, "%s: Unexpected register read [bar %u, offset %lx "
		"size %d]\n", __func__, baridx, offset, size);

	return 0;
}

static void
ptnet_bar_write(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
	      int baridx, uint64_t offset, int size, uint64_t value)
{
	struct ptnet_softc *sc = pi->pi_arg;

	if (sc == NULL)
		return;

	fprintf(stderr, "%s: Unexpected register write [bar %u, offset %lx "
		"size %d value %lx]\n", __func__, baridx, offset, size, value);
}

/* PCI device initialization. */
static int
ptnet_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	struct ptnet_softc *sc;
	char *ptopts, *devname;
	uint8_t macaddr[6];
	int mac_provided = 0;
	int ret;

	sc = calloc(1, sizeof(*sc));
	if (sc == NULL) {
		fprintf(stderr, "%s: out of memory\n", __func__);
		return -1;
	}

	/* Link our softc in the pci_devinst. */
	pi->pi_arg = sc;
	sc->pi = pi;

	/* Parse command line options. */
	if (opts == NULL) {
		fprintf(stderr, "%s: No backend specified\n", __func__);
		return -1;
	}

	devname = ptopts = strdup(opts);
	(void) strsep(&ptopts, ",");

	if (ptopts != NULL) {
		ret = net_parsemac(ptopts, macaddr);
		if (ret != 0) {
			free(devname);
			return ret;
		}
		mac_provided = 1;
	}

	if (!mac_provided) {
		net_genmac(pi, macaddr);
	}

	/* Initialize backend. */
	sc->be = netbe_init(devname, NULL, sc);
	if (!sc->be) {
		fprintf(stderr, "net backend initialization failed\n");
	}

	free(devname);

	sc->ptbe = get_ptnetmap(sc->be);
	if (!sc->ptbe) {
		fprintf(stderr, "%s: failed to get ptnetmap\n", __func__);
		return -1;
	}

	/* Initialize PCI configuration space. */
	pci_set_cfgdata16(pi, PCIR_VENDOR, PTNETMAP_PCI_VENDOR_ID);
	pci_set_cfgdata16(pi, PCIR_DEVICE, PTNETMAP_PCI_NETIF_ID);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_NETWORK);
	pci_set_cfgdata8(pi, PCIR_SUBCLASS, PCIS_NETWORK_ETHERNET);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, 1);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, PTNETMAP_PCI_VENDOR_ID);

	/* Allocate a BAR for an I/O region. */
	ret = pci_emul_alloc_bar(pi, PTNETMAP_IO_PCI_BAR, PCIBAR_IO,
				 PTNET_IO_MASK + 1);
	if (ret) {
		fprintf(stderr, "%s: failed to allocate BAR [%d]\n",
			__func__, ret);
		return ret;
	}

	/* Initialize registers and data structures. */
	memset(sc->ioregs, 0, sizeof(sc->ioregs));
	sc->csb = NULL;
	sc->ptbe = NULL;
	sc->ioregs[PTNET_IO_MAC_HI >> 2] = (macaddr[0] << 8) | macaddr[1];
	sc->ioregs[PTNET_IO_MAC_LO >> 2] = (macaddr[2] << 24) |
					   (macaddr[3] << 16) |
					   (macaddr[4] << 8) | macaddr[5];

	sc->num_rings = 0;
	ptnet_get_netmap_if(sc);

	/* Allocate a BAR for MSI-X vectors. */
	pci_emul_add_msixcap(pi, sc->num_rings, PTNETMAP_MSIX_PCI_BAR);

	return 0;
}

struct pci_devemu pci_de_ptnet = {
	.pe_emu = 	"ptnet",
	.pe_init =	ptnet_init,
	.pe_barwrite =	ptnet_bar_write,
	.pe_barread =	ptnet_bar_read,
};
PCI_EMUL_SET(pci_de_ptnet);
