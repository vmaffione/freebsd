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

/*
 * This file contains the emulation of the ptnet network frontend, to be used
 * with netmap backend.
 */

#ifdef WITH_NETMAP

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <net/if.h>	/* IFNAMSIZ */
#include <net/netmap.h>
#include <net/netmap_virt.h>

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/_cpuset.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>	/* VM_LAPIC_MSI */
#include <vmmapi.h>

#include "bhyverun.h"
#include "pci_emul.h"
#include "net_utils.h"
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

static int
ptnet_ptctl_create(struct ptnet_softc *sc)
{
	struct ptnetmap_cfgentry_bhyve *cfgentry;
	struct pci_devinst *pi = sc->pi;
	struct vmctx *vmctx = pi->pi_vmctx;
	struct ptnetmap_cfg *cfg;
	unsigned int kick_addr;
	int ret;
	int i;

	if (sc->csb == NULL) {
		fprintf(stderr, "%s: Unexpected NULL CSB", __func__);
		return -1;
	}

	cfg = calloc(1, sizeof(*cfg) + sc->num_rings * sizeof(*cfgentry));

	cfg->cfgtype = PTNETMAP_CFGTYPE_BHYVE;
	cfg->entry_size = sizeof(*cfgentry);
	cfg->num_rings = sc->num_rings;
	cfg->ptrings = sc->csb;

	kick_addr = pi->pi_bar[PTNETMAP_IO_PCI_BAR].addr + PTNET_IO_KICK_BASE;
	cfgentry = (struct ptnetmap_cfgentry_bhyve *)(cfg + 1);

	for (i = 0; i < sc->num_rings; i++, kick_addr += 4, cfgentry++) {
		struct msix_table_entry *mte;
		uint64_t cookie = sc->ioregs[PTNET_IO_MAC_LO >> 2] + 4*i;

		cfgentry->ioctl_fd = vm_get_fd(vmctx);
		cfgentry->ioctl_cmd = VM_LAPIC_MSI;
		mte = &pi->pi_msix.table[i];
		cfgentry->ioctl_data.addr = mte->addr;
		cfgentry->ioctl_data.msg_data = mte->msg_data;

		fprintf(stderr, "%s: vector %u, addr %lu, data %u, "
				"kick_addr %u, cookie: %p\n",
			__func__, i, mte->addr, mte->msg_data, kick_addr,
			(void*)cookie);

		ret = vm_io_reg_handler(vmctx, kick_addr /* ioaddr */,
					0 /* in */, 0 /* mask_data */,
					0 /* data */, VM_IO_REGH_KWEVENTS,
					(void*)cookie /* cookie */);
		if (ret) {
			fprintf(stderr, "%s: vm_io_reg_handler %d\n",
				__func__, ret);
		}
		cfgentry->wchan = (uint64_t) cookie;
	}

	ret = ptnetmap_create(sc->ptbe, cfg);
	free(cfg);

	return ret;
}

static int
ptnet_ptctl_delete(struct ptnet_softc *sc)
{
	struct pci_devinst *pi = sc->pi;
	struct vmctx *vmctx = pi->pi_vmctx;
	unsigned int kick_addr;
	int i;

	kick_addr = pi->pi_bar[PTNETMAP_IO_PCI_BAR].addr + PTNET_IO_KICK_BASE;

	for (i = 0; i < sc->num_rings; i++, kick_addr += 4) {
		vm_io_reg_handler(vmctx, kick_addr, 0, 0, 0,
				  VM_IO_REGH_DELETE, 0);
	}

	return ptnetmap_delete(sc->ptbe);
}

static void
ptnet_ptctl(struct ptnet_softc *sc, uint64_t cmd)
{
	int ret = EINVAL;

	switch (cmd) {
	case PTNETMAP_PTCTL_CREATE:
		/* React to a REGIF in the guest. */
		ret = ptnet_ptctl_create(sc);
		break;

	case PTNETMAP_PTCTL_DELETE:
		/* React to an UNREGIF in the guest. */
		ret = ptnet_ptctl_delete(sc);
		break;
	}

	sc->ioregs[PTNET_IO_PTCTL >> 2] = ret;
}

static void
ptnet_csb_mapping(struct ptnet_softc *sc)
{
	uint64_t base = ((uint64_t)sc->ioregs[PTNET_IO_CSBBAH >> 2] << 32) |
			sc->ioregs[PTNET_IO_CSBBAL >> 2];
	uint64_t len = 4096;

	sc->csb = NULL;
	if (base) {
		sc->csb = paddr_guest2host(sc->pi->pi_vmctx, base, len);
	}
}

static void
ptnet_bar_write(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
	      int baridx, uint64_t offset, int size, uint64_t value)
{
	struct ptnet_softc *sc = pi->pi_arg;
	unsigned int index;

	/* Redirect to MSI-X emulation code. */
	if (baridx == pci_msix_table_bar(pi) ||
			baridx == pci_msix_pba_bar(pi)) {
		pci_emul_msix_twrite(pi, offset, size, value);
		return;
	}

	if (sc == NULL)
		return;

	offset &= PTNET_IO_MASK;
	index = offset >> 2;

	if (baridx != PTNETMAP_IO_PCI_BAR || offset >= PTNET_IO_END) {
		fprintf(stderr, "%s: Unexpected register write [bar %u, "
			"offset %lx size %d value %lx]\n", __func__, baridx,
			offset, size, value);
		return;
	}

	switch (offset) {
	case PTNET_IO_PTFEAT:
		value = ptnetmap_ack_features(sc->ptbe, value);
		sc->ioregs[index] = value;
		break;

	case PTNET_IO_PTCTL:
		ptnet_ptctl(sc, value);
		break;

	case PTNET_IO_CSBBAH:
		sc->ioregs[index] = value;
		break;

	case PTNET_IO_CSBBAL:
		sc->ioregs[index] = value;
		ptnet_csb_mapping(sc);
		break;

	case PTNET_IO_VNET_HDR_LEN:
		if (netbe_set_cap(sc->be, netbe_get_cap(sc->be),
				  value) == 0) {
			sc->ioregs[index] = value;
		}
		break;
	}
}

static uint64_t
ptnet_bar_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
	       int baridx, uint64_t offset, int size)
{
	struct ptnet_softc *sc = pi->pi_arg;
	uint64_t index = offset >> 2;

	if (baridx == pci_msix_table_bar(pi) ||
			baridx == pci_msix_pba_bar(pi)) {
		return pci_emul_msix_tread(pi, offset, size);
	}

	if (sc == NULL)
		return 0;

	offset &= PTNET_IO_MASK;

	if (baridx != PTNETMAP_IO_PCI_BAR || offset >= PTNET_IO_END) {
		fprintf(stderr, "%s: Unexpected register read [bar %u, "
			"offset %lx size %d]\n", __func__, baridx, offset,
			size);
		return 0;
	}

	switch (offset) {
		case PTNET_IO_NIFP_OFS:
		case PTNET_IO_NUM_TX_RINGS:
		case PTNET_IO_NUM_RX_RINGS:
		case PTNET_IO_NUM_TX_SLOTS:
		case PTNET_IO_NUM_RX_SLOTS:
			/* Fill in device registers with information about
			 * nifp_offset, num_*x_rings, and num_*x_slots. */
			ptnet_get_netmap_if(sc);
			break;

		case PTNET_IO_HOSTMEMID:
			sc->ioregs[index] = ptnetmap_get_hostmemid(sc->ptbe);
			break;
	}

	return sc->ioregs[index];
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

	/* Initialize backend. A NULL callback is used here to tell
	 * the ask the netmap backend to use ptnetmap. */
	sc->be = netbe_init(devname, NULL, sc);
	if (!sc->be) {
		fprintf(stderr, "net backend initialization failed\n");
		return -1;
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

#endif /* WITH_NETMAP */
