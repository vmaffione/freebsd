/*
 * Copyright (C) 2015 Stefano Garzarella (stefano.garzarella@gmail.com)
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

#ifdef WITH_NETMAP

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <net/if.h>	/* IFNAMSIZ */
#include <net/netmap.h>
#include <net/netmap_virt.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include "bhyverun.h"
#include "pci_emul.h"

/*
 * ptnetmap memdev PCI device
 *
 * This device is used to map a netmap memory allocator on the guest VM
 * through PCI_BAR. The same allocator can be shared between multiple ptnetmap
 * ports in the guest.
 *
 * Each netmap allocator has a unique ID assigned by the netmap host module.
 *
 * The implementation here is based on the QEMU/KVM one.
 */
struct ptn_memdev_softc {
	struct pci_devinst *pi;		/* PCI device instance */

	void *mem_ptr;			/* netmap shared memory */
	struct netmap_pools_info info;

	TAILQ_ENTRY(ptn_memdev_softc) next;
};
static TAILQ_HEAD(, ptn_memdev_softc) ptn_memdevs = TAILQ_HEAD_INITIALIZER(ptn_memdevs);

/*
 * ptn_memdev_softc can be created by pe_init or ptnetmap backend,
 * this depends on the order of initialization.
 */
static struct ptn_memdev_softc *
ptn_memdev_create()
{
	struct ptn_memdev_softc *sc;

	sc = calloc(1, sizeof(struct ptn_memdev_softc));
	if (sc != NULL) {
		TAILQ_INSERT_TAIL(&ptn_memdevs, sc, next);
	}

	return sc;
}

static void
ptn_memdev_delete(struct ptn_memdev_softc *sc)
{
	TAILQ_REMOVE(&ptn_memdevs, sc, next);

	free(sc);
}

/*
 * Find ptn_memdev through memid (netmap memory allocator ID)
 */
static struct ptn_memdev_softc *
ptn_memdev_find_memid(uint32_t mem_id)
{
	struct ptn_memdev_softc *sc;

	TAILQ_FOREACH(sc, &ptn_memdevs, next) {
		if (sc->mem_ptr != NULL && mem_id == sc->info.memid) {
			return sc;
		}
	}

	return NULL;
}

/*
 * Find ptn_memdev that has not netmap memory (attached by ptnetmap backend)
 */
static struct ptn_memdev_softc *
ptn_memdev_find_empty_mem()
{
	struct ptn_memdev_softc *sc;

	TAILQ_FOREACH(sc, &ptn_memdevs, next) {
		if (sc->mem_ptr == NULL) {
			return sc;
		}
	}

	return NULL;
}

/*
 * Find ptn_memdev that has not PCI device istance (created by pe_init)
 */
static struct ptn_memdev_softc *
ptn_memdev_find_empty_pi()
{
	struct ptn_memdev_softc *sc;

	TAILQ_FOREACH(sc, &ptn_memdevs, next) {
		if (sc->pi == NULL) {
			return sc;
		}
	}

	return NULL;
}

/*
 * Handle read on ptnetmap-memdev register
 */
static uint64_t
ptn_pci_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
	     int baridx, uint64_t offset, int size)
{
	struct ptn_memdev_softc *sc = pi->pi_arg;

	if (sc == NULL)
		return 0;

	if (baridx == PTNETMAP_IO_PCI_BAR) {
		switch (offset) {
		case PTNET_MDEV_IO_MEMSIZE_LO:
			return sc->info.memsize & 0xffffffff;
		case PTNET_MDEV_IO_MEMSIZE_HI:
			return sc->info.memsize >> 32;
		case PTNET_MDEV_IO_MEMID:
			return sc->info.memid;
		case PTNET_MDEV_IO_IF_POOL_OFS:
			return sc->info.if_pool_offset;
		case PTNET_MDEV_IO_IF_POOL_OBJNUM:
			return sc->info.if_pool_objtotal;
		case PTNET_MDEV_IO_IF_POOL_OBJSZ:
			return sc->info.if_pool_objsize;
		case PTNET_MDEV_IO_RING_POOL_OFS:
			return sc->info.ring_pool_offset;
		case PTNET_MDEV_IO_RING_POOL_OBJNUM:
			return sc->info.ring_pool_objtotal;
		case PTNET_MDEV_IO_RING_POOL_OBJSZ:
			return sc->info.ring_pool_objsize;
		case PTNET_MDEV_IO_BUF_POOL_OFS:
			return sc->info.buf_pool_offset;
		case PTNET_MDEV_IO_BUF_POOL_OBJNUM:
			return sc->info.buf_pool_objtotal;
		case PTNET_MDEV_IO_BUF_POOL_OBJSZ:
			return sc->info.buf_pool_objsize;
		}
	}

	printf("%s: Unexpected register read [bar %u, offset %lx size %d]\n",
		__func__, baridx, offset, size);

	return 0;
}

/*
 * Handle write on ptnetmap-memdev register (unused for now)
 */
static void
ptn_pci_write(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
	      int baridx, uint64_t offset, int size, uint64_t value)
{
	struct ptn_memdev_softc *sc = pi->pi_arg;

	if (sc == NULL)
		return;

	printf("%s: Unexpected register write [bar %u, offset %lx size %d "
	       "value %lx]\n", __func__, baridx, offset, size, value);
}

/*
 * Configure the ptnetmap-memdev PCI BARs. PCI BARs can only be created
 * when the PCI device is created and the netmap memory is attached.
 */
static int
ptn_memdev_configure_bars(struct ptn_memdev_softc *sc)
{
	int ret;

	if (sc->pi == NULL || sc->mem_ptr == NULL)
		return 0;

	/* Allocate a BAR for an I/O region. */
	ret = pci_emul_alloc_bar(sc->pi, PTNETMAP_IO_PCI_BAR, PCIBAR_IO,
				 PTNET_MDEV_IO_END);
	if (ret) {
		printf("ptnetmap_memdev: iobar allocation error %d\n", ret);
		return ret;
	}

	/* Allocate a BAR for a memory region. */
	ret = pci_emul_alloc_bar(sc->pi, PTNETMAP_MEM_PCI_BAR, PCIBAR_MEM32,
			sc->info.memsize);
	if (ret) {
		printf("ptnetmap_memdev: membar allocation error %d\n", ret);
		return ret;
	}

	/* Map netmap memory on the memory BAR. */
	ret = vm_map_user_buf(sc->pi->pi_vmctx,
			      sc->pi->pi_bar[PTNETMAP_MEM_PCI_BAR].addr,
			      sc->info.memsize, sc->mem_ptr, 1);
	if (ret) {
		printf("ptnetmap_memdev: membar map error %d\n", ret);
		return ret;
	}

	return 0;
}

/*
 * PCI device initialization
 */
static int
ptn_memdev_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	struct ptn_memdev_softc *sc;
	int ret;

	sc = ptn_memdev_find_empty_pi();
	if (sc == NULL) {
		sc = ptn_memdev_create();
		if (sc == NULL) {
			printf("ptnetmap_memdev: calloc error\n");
			return (ENOMEM);
		}
	}

	/* Link our softc in the pci_devinst. */
	pi->pi_arg = sc;
	sc->pi = pi;

	/* Initialize PCI configuration space. */
	pci_set_cfgdata16(pi, PCIR_VENDOR, PTNETMAP_PCI_VENDOR_ID);
	pci_set_cfgdata16(pi, PCIR_DEVICE, PTNETMAP_PCI_DEVICE_ID);
	pci_set_cfgdata8(pi, PCIR_CLASS, PCIC_NETWORK);
	pci_set_cfgdata16(pi, PCIR_SUBDEV_0, 1);
	pci_set_cfgdata16(pi, PCIR_SUBVEND_0, PTNETMAP_PCI_VENDOR_ID);

	/* Configure PCI-BARs. */
	ret = ptn_memdev_configure_bars(sc);
	if (ret) {
		printf("ptnetmap_memdev: configure error\n");
		goto err;
	}

	return 0;
err:
	ptn_memdev_delete(sc);
	pi->pi_arg = NULL;
	return ret;
}

/*
 * used by ptnetmap backend to attach the netmap memory allocator to the
 * ptnetmap-memdev. (shared with the guest VM through PCI-BAR)
 */
int
ptn_memdev_attach(void *mem_ptr, struct netmap_pools_info *info)
{
	struct ptn_memdev_softc *sc;
	int ret;

	/* if a device with the same mem_id is already attached, we are done */
	if (ptn_memdev_find_memid(info->memid)) {
		printf("ptnetmap_memdev: already attched\n");
		return 0;
	}

	sc = ptn_memdev_find_empty_mem();
	if (sc == NULL) {
		sc = ptn_memdev_create();
		if (sc == NULL) {
			printf("ptnetmap_memdev: calloc error\n");
			return (ENOMEM);
		}
	}

	sc->mem_ptr = mem_ptr;
	sc->info = *info;

	/* configure device PCI-BARs */
	ret = ptn_memdev_configure_bars(sc);
	if (ret) {
		printf("ptnetmap_memdev: configure error\n");
		goto err;
	}


	return 0;
err:
	ptn_memdev_delete(sc);
	sc->pi->pi_arg = NULL;
	return ret;
}

struct pci_devemu pci_de_ptnetmap = {
	.pe_emu = 	PTNETMAP_MEMDEV_NAME,
	.pe_init =	ptn_memdev_init,
	.pe_barwrite =	ptn_pci_write,
	.pe_barread =	ptn_pci_read
};
PCI_EMUL_SET(pci_de_ptnetmap);

#endif /* WITH_NETMAP */
