/*
 * Copyright (C) 2014-2018 Vincenzo Maffione, Luigi Rizzo.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 * $FreeBSD$
 */

#include <net/netmap.h>
#include <sys/selinfo.h>
#include <vm/vm.h>
#include <vm/pmap.h>    /* vtophys ? */
#include <dev/netmap/netmap_kern.h>

/*
 * Return 1 if the queue identified by 't' and 'idx' is in netmap mode.
 */
static int
vtnet_netmap_queue_on(struct vtnet_softc *sc, enum txrx t, int idx)
{
	struct netmap_adapter *na = NA(sc->vtnet_ifp);

	if (!nm_native_on(na))
		return 0;

	if (t == NR_RX)
		return !!(idx < na->num_rx_rings &&
			na->rx_rings[idx]->nr_mode == NKR_NETMAP_ON);

	return !!(idx < na->num_tx_rings &&
		na->tx_rings[idx]->nr_mode == NKR_NETMAP_ON);
}

static void
vtnet_free_used(struct virtqueue *vq, int netmap_bufs, enum txrx t, int idx)
{
	void *cookie;
	int deq = 0;

	while ((cookie = virtqueue_dequeue(vq, NULL)) != NULL) {
		if (netmap_bufs) {
			/* These are netmap buffers: there is nothing to do. */
		} else {
			/* These are mbufs that we need to free. */
			struct mbuf *m;

			if (t == NR_TX) {
				struct vtnet_tx_header *txhdr = cookie;
				m = txhdr->vth_mbuf;
				m_freem(m);
				uma_zfree(vtnet_tx_header_zone, txhdr);
			} else {
				m = cookie;
				m_freem(m);
			}
		}
		deq++;
	}

	if (deq)
		nm_prinf("%d sgs dequeued from %s-%d (netmap=%d)\n",
			 deq, nm_txrx2str(t), idx, netmap_bufs);
}

/* Register and unregister. */
static int
vtnet_netmap_reg(struct netmap_adapter *na, int onoff)
{
        struct ifnet *ifp = na->ifp;
	struct vtnet_softc *sc = ifp->if_softc;
	int success;
	enum txrx t;
	int i;

	/* Drain the taskqueues to make sure that there are no worker threads
	 * accessing the virtqueues. */
	vtnet_drain_taskqueues(sc);

	VTNET_CORE_LOCK(sc);

	/* We need nm_netmap_on() to return true when called by
	 * vtnet_init_locked() below. */
	if (onoff)
		nm_set_native_flags(na);

	/* We need to trigger a device reset in order to unexpose guest buffers
	 * published to the host. */
	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);
	/* Get pending used buffers. The way they are freed depends on whether
	 * they are netmap buffer or they are mbufs. We can tell apart the two
	 * cases by looking at kring->nr_mode, before this is possibly updated
	 * in the loop below. */
	for (i = 0; i < sc->vtnet_act_vq_pairs; i++) {
		struct vtnet_txq *txq = &sc->vtnet_txqs[i];
		struct vtnet_rxq *rxq = &sc->vtnet_rxqs[i];
		struct netmap_kring *kring;

		VTNET_TXQ_LOCK(txq);
		kring = NMR(na, NR_TX)[i];
		vtnet_free_used(txq->vtntx_vq,
				kring->nr_mode == NKR_NETMAP_ON, NR_TX, i);
		VTNET_TXQ_UNLOCK(txq);

		VTNET_RXQ_LOCK(rxq);
		kring = NMR(na, NR_RX)[i];
		vtnet_free_used(rxq->vtnrx_vq,
				kring->nr_mode == NKR_NETMAP_ON, NR_RX, i);
		VTNET_RXQ_UNLOCK(rxq);
	}
	vtnet_init_locked(sc);
	success = (ifp->if_drv_flags & IFF_DRV_RUNNING) ? 0 : ENXIO;

	if (onoff) {
		for_rx_tx(t) {
			/* Hardware rings. */
			for (i = 0; i < nma_get_nrings(na, t); i++) {
				struct netmap_kring *kring = NMR(na, t)[i];

				if (nm_kring_pending_on(kring))
					kring->nr_mode = NKR_NETMAP_ON;
			}

			/* Host rings. */
			for (i = 0; i < nma_get_host_nrings(na, t); i++) {
				struct netmap_kring *kring =
					NMR(na, t)[nma_get_nrings(na, t) + i];

				if (nm_kring_pending_on(kring))
					kring->nr_mode = NKR_NETMAP_ON;
			}
		}
	} else {
		nm_clear_native_flags(na);
		for_rx_tx(t) {
			/* Hardware rings. */
			for (i = 0; i < nma_get_nrings(na, t); i++) {
				struct netmap_kring *kring = NMR(na, t)[i];

				if (nm_kring_pending_off(kring))
					kring->nr_mode = NKR_NETMAP_OFF;
			}

			/* Host rings. */
			for (i = 0; i < nma_get_host_nrings(na, t); i++) {
				struct netmap_kring *kring =
					NMR(na, t)[nma_get_nrings(na, t) + i];

				if (nm_kring_pending_off(kring))
					kring->nr_mode = NKR_NETMAP_OFF;
			}
		}
	}

	VTNET_CORE_UNLOCK(sc);

	return success;
}


/* Reconcile kernel and user view of the transmit ring. */
static int
vtnet_netmap_txsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	//u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;

	/* device-specific */
	struct vtnet_softc *sc = ifp->if_softc;
	struct vtnet_txq *txq = &sc->vtnet_txqs[ring_nr];
	struct virtqueue *vq = txq->vtntx_vq;
	int interrupts = !(kring->nr_kflags & NKR_NOINTR);

	/*
	 * First part: process new packets to send.
	 */
	rmb();

	nm_i = kring->nr_hwcur;
	if (nm_i != head) {	/* we have new packets to send */
		struct sglist *sg = txq->vtntx_sg;

		//nic_i = netmap_idx_k2n(kring, nm_i);
		for (n = 0; nm_i != head; n++) {
			/* we use an empty header here */
			struct netmap_slot *slot = &ring->slot[nm_i];
			u_int len = slot->len;
			uint64_t paddr;
			void *addr = PNMB(na, slot, &paddr);
                        int err;

			NM_CHECK_ADDR_LEN(na, addr, len);

			slot->flags &= ~(NS_REPORT | NS_BUF_CHANGED);
			/* Initialize the scatterlist, expose it to the hypervisor,
			 * and kick the hypervisor (if necessary).
			 */
			sglist_reset(sg); // cheap
			// TODO cache physical address of vtntx_shrhdr
			err = sglist_append(sg, &txq->vtntx_shrhdr, sc->vtnet_hdr_size);
			err = sglist_append_phys(sg, paddr, len);
                        err = virtqueue_enqueue(vq, /*cookie=*/txq, sg,
						/*readable=*/sg->sg_nseg,
						/*writeable=*/0);
                        if (unlikely(err < 0)) {
                                nm_prerr("virtqueue_enqueue() failed: %d\n", err);
                                break;
                        }

			nm_i = nm_next(nm_i, lim);
			//nic_i = nm_next(nic_i, lim);
		}

		virtqueue_notify(vq);

		/* Update hwcur depending on where we stopped. */
		kring->nr_hwcur = nm_i; /* note we migth break early */
	}

        /* Free used slots. We only consider our own used buffers, recognized
	 * by the token we passed to virtqueue_enqueue.
	 */
        n = 0;
        for (;;) {
                void *token = virtqueue_dequeue(vq, NULL);
                if (token == NULL)
                        break;
		if (unlikely(token != (void *)txq))
			nm_prerr("BUG: TX token mismatch!\n");
		else
			n++;
        }
	if (n > 0) {
		kring->nr_hwtail += n;
		if (kring->nr_hwtail > lim)
			kring->nr_hwtail -= lim + 1;
	}

	if (interrupts && virtqueue_nfree(vq) < 32)
		virtqueue_postpone_intr(vq, VQ_POSTPONE_LONG);

        return 0;
}

static int
vtnet_netmap_kring_refill(struct netmap_kring *kring, u_int nm_i, u_int head)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int const lim = kring->nkr_num_slots - 1;

	/* device-specific */
	struct vtnet_softc *sc = ifp->if_softc;
	struct vtnet_rxq *rxq = &sc->vtnet_rxqs[ring_nr];
	struct virtqueue *vq = rxq->vtnrx_vq;

	/* use a local sglist, default might be short */
	struct sglist_seg ss[2];
	struct sglist sg = { ss, 0, 0, 2 };

	for (; nm_i != head; nm_i = nm_next(nm_i, lim)) {
		struct netmap_slot *slot = &ring->slot[nm_i];
		uint64_t paddr;
		void *addr = PNMB(na, slot, &paddr);
		int err = 0;

		if (addr == NETMAP_BUF_BASE(na)) { /* bad buf */
			if (netmap_ring_reinit(kring))
				return -1;
		}

		slot->flags &= ~NS_BUF_CHANGED;
		sglist_reset(&sg);
		err = sglist_append(&sg, &rxq->vtnrx_shrhdr, sc->vtnet_hdr_size);
		err = sglist_append_phys(&sg, paddr, NETMAP_BUF_SIZE(na));
		/* writable for the host */
		err = virtqueue_enqueue(vq, /*cookie=*/rxq, &sg,
				/*readable=*/0, /*writeable=*/sg.sg_nseg);
		if (err < 0) {
			D("virtqueue_enqueue failed");
			break;
		}
	}

	return nm_i;
}

/*
 * Publish netmap buffers on a RX virtqueue.
 * Returns -1 if this virtqueue is not being opened in netmap mode.
 * If the virtqueue is being opened in netmap mode, return 0 on success and
 * a positive error code on failure.
 */
static int
vtnet_netmap_rxq_populate(struct vtnet_rxq *rxq)
{
	struct netmap_adapter *na = NA(rxq->vtnrx_sc->vtnet_ifp);
	struct netmap_kring *kring;
	int error;

	if (!nm_native_on(na) || rxq->vtnrx_id >= na->num_rx_rings)
		return -1;

	kring = na->rx_rings[rxq->vtnrx_id];
	if (!(nm_kring_pending_on(kring) ||
			kring->nr_pending_mode == NKR_NETMAP_ON))
		return -1;

	error = vtnet_netmap_kring_refill(kring, 0, na->num_rx_desc-1);
	virtqueue_notify(rxq->vtnrx_vq);

	nm_prinf("%s: %d bufs populated\n", kring->name, error);

	return error < 0 ? ENXIO : 0;
}

/* Reconcile kernel and user view of the receive ring. */
static int
vtnet_netmap_rxsync(struct netmap_kring *kring, int flags)
{
	struct netmap_adapter *na = kring->na;
        struct ifnet *ifp = na->ifp;
	struct netmap_ring *ring = kring->ring;
	u_int ring_nr = kring->ring_id;
	u_int nm_i;	/* index into the netmap ring */
	// u_int nic_i;	/* index into the NIC ring */
	u_int n;
	u_int const lim = kring->nkr_num_slots - 1;
	u_int const head = kring->rhead;
	int force_update = (flags & NAF_FORCE_READ) ||
				(kring->nr_kflags & NKR_PENDINTR);
	int interrupts = !(kring->nr_kflags & NKR_NOINTR);

	/* device-specific */
	struct vtnet_softc *sc = ifp->if_softc;
	struct vtnet_rxq *rxq = &sc->vtnet_rxqs[ring_nr];
	struct virtqueue *vq = rxq->vtnrx_vq;

	vtnet_rxq_disable_intr(rxq);

	rmb();
	/*
	 * First part: import newly received packets.
	 * Only accept our own buffers (matching the token). We should only get
	 * matching buffers, because of vtnet_netmap_free_rx_unused_bufs()
	 * and vtnet_netmap_init_buffers(). We may need to stop early to avoid
	 * hwtail to overrun hwcur.
	 */
	if (netmap_no_pendintr || force_update) {
		uint32_t hwtail_lim = nm_prev(kring->nr_hwcur, lim);
                void *token;

                nm_i = kring->nr_hwtail;
                n = 0;
		while (nm_i != hwtail_lim) {
			int len;
                        token = virtqueue_dequeue(vq, &len);
                        if (token == NULL)
                                break;
			if (unlikely(token != (void *)rxq)) {
				nm_prerr("BUG: RX token mismatch!\n");
			} else {
				/* Skip the virtio-net header. */
				len -= sc->vtnet_hdr_size;
				if (unlikely(len < 0)) {
					RD(1, "Truncated virtio-net-header, "
						"missing %d bytes", -len);
					len = 0;
				}
				ring->slot[nm_i].len = len;
				ring->slot[nm_i].flags = 0;
				nm_i = nm_next(nm_i, lim);
				n++;
                        }
		}
		kring->nr_hwtail = nm_i;
		kring->nr_kflags &= ~NKR_PENDINTR;
	}
        ND("[B] h %d c %d hwcur %d hwtail %d",
		ring->head, ring->cur, kring->nr_hwcur,
			      kring->nr_hwtail);

	/*
	 * Second part: skip past packets that userspace has released.
	 */
	nm_i = kring->nr_hwcur; /* netmap ring index */
	if (nm_i != head) {
		int nm_j = vtnet_netmap_kring_refill(kring, nm_i, head);
		if (nm_j < 0)
			return nm_j;
		kring->nr_hwcur = nm_j;
		virtqueue_notify(vq);
	}

	/* We have finished processing used RX buffers, so we have to tell
	 * the hypervisor to make a call when more used RX buffers are ready.
	 */
	if (interrupts) {
		vtnet_rxq_enable_intr(rxq);
	}

        ND("[C] h %d c %d t %d hwcur %d hwtail %d",
		ring->head, ring->cur, ring->tail,
		kring->nr_hwcur, kring->nr_hwtail);

	return 0;
}


/* Enable/disable interrupts on all virtqueues. */
static void
vtnet_netmap_intr(struct netmap_adapter *na, int onoff)
{
	struct vtnet_softc *sc = na->ifp->if_softc;
	int i;

	for (i = 0; i < sc->vtnet_max_vq_pairs; i++) {
		struct vtnet_rxq *rxq = &sc->vtnet_rxqs[i];
		struct vtnet_txq *txq = &sc->vtnet_txqs[i];
		struct virtqueue *txvq = txq->vtntx_vq;

		if (onoff) {
			vtnet_rxq_enable_intr(rxq);
			virtqueue_enable_intr(txvq);
		} else {
			vtnet_rxq_disable_intr(rxq);
			virtqueue_disable_intr(txvq);
		}
	}
}

static void
vtnet_netmap_attach(struct vtnet_softc *sc)
{
	struct netmap_adapter na;

	bzero(&na, sizeof(na));

	na.ifp = sc->vtnet_ifp;
	na.na_flags = 0;
	na.num_tx_desc = virtqueue_size(sc->vtnet_txqs[0].vtntx_vq);
	na.num_rx_desc = virtqueue_size(sc->vtnet_rxqs[0].vtnrx_vq);
	na.num_tx_rings = na.num_rx_rings = sc->vtnet_max_vq_pairs;
	na.rx_buf_maxsize = 0;
	na.nm_register = vtnet_netmap_reg;
	na.nm_txsync = vtnet_netmap_txsync;
	na.nm_rxsync = vtnet_netmap_rxsync;
	na.nm_intr = vtnet_netmap_intr;
	na.nm_config = NULL; // TODO

	netmap_attach(&na);

        nm_prinf("vtnet attached txq=%d, txd=%d rxq=%d, rxd=%d\n",
			na.num_tx_rings, na.num_tx_desc,
			na.num_tx_rings, na.num_rx_desc);
}
/* end of file */
