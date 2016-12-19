/*-
 * Copyright (c) 2014 Tycho Nightingale <tycho.nightingale@pluribusnetworks.com>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
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

#include <sys/param.h>
#include <sys/systm.h>

#include <machine/vmm.h>
#include <machine/vmm_instruction_emul.h>

#include "vatpic.h"
#include "vatpit.h"
#include "vpmtmr.h"
#include "vrtc.h"
#include "vmm_ioport.h"
#include "vmm_ktr.h"

#define	MAX_IOPORTS		1280

ioport_handler_func_t ioport_handler[MAX_IOPORTS] = {
	[TIMER_MODE] = vatpit_handler,
	[TIMER_CNTR0] = vatpit_handler,
	[TIMER_CNTR1] = vatpit_handler,
	[TIMER_CNTR2] = vatpit_handler,
	[NMISC_PORT] = vatpit_nmisc_handler,
	[IO_ICU1] = vatpic_master_handler,
	[IO_ICU1 + ICU_IMR_OFFSET] = vatpic_master_handler,
	[IO_ICU2] = vatpic_slave_handler,
	[IO_ICU2 + ICU_IMR_OFFSET] = vatpic_slave_handler,
	[IO_ELCR1] = vatpic_elc_handler,
	[IO_ELCR2] = vatpic_elc_handler,
	[IO_PMTMR] = vpmtmr_handler,
	[IO_RTC] = vrtc_addr_handler,
	[IO_RTC + 1] = vrtc_data_handler,
};

#ifdef KTR
static const char *
inout_instruction(struct vm_exit *vmexit)
{
	int index;

	static const char *iodesc[] = {
		"outb", "outw", "outl",
		"inb", "inw", "inl",
		"outsb", "outsw", "outsd",
		"insb", "insw", "insd",
	};

	switch (vmexit->u.inout.bytes) {
	case 1:
		index = 0;
		break;
	case 2:
		index = 1;
		break;
	default:
		index = 2;
		break;
	}

	if (vmexit->u.inout.in)
		index += 3;

	if (vmexit->u.inout.string)
		index += 6;

	KASSERT(index < nitems(iodesc), ("%s: invalid index %d",
	    __func__, index));

	return (iodesc[index]);
}
#endif	/* KTR */

#ifdef VMM_IOPORT_REG_HANDLER
#include <sys/kernel.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/malloc.h>
#include <sys/systm.h>

static MALLOC_DEFINE(M_IOREGH, "ioregh", "bhyve ioport reg handlers");

#define IOPORT_MAX_REG_HANDLER	16

/*
 * ioport_reg_handler functions allows us to to catch VM write/read
 * on specific I/O address and send notification.
 *
 * When the VM writes or reads a specific value on I/O address, if the address
 * and the value matches with the info stored durign the handler registration,
 * then we send a notification (we can have multiple type of notification,
 * but for now is implemented only the VM_IO_REGH_KWEVENTS handler.
 */

typedef int (*ioport_reg_handler_func_t)(struct vm *vm,
		struct ioport_reg_handler *regh, uint32_t *val);

struct ioport_reg_handler {
	uint16_t port;				/* I/O address */
	uint16_t in;				/* 0 out, 1 in */
	uint32_t mask_data;			/* 0 means match anything */
	uint32_t data;				/* data to match */
	ioport_reg_handler_func_t handler;	/* handler pointer */
	void *handler_arg;			/* handler argument */
};

struct ioregh {
	struct sx lock;
	/* TODO: use hash table */
	struct ioport_reg_handler handlers[IOPORT_MAX_REG_HANDLER];
};

/* ----- I/O reg handlers ----- */

/*
 * VM_IO_REGH_KWEVENTS handler
 *
 * wakeup() on specified address that uniquely identifies the event
 *
 */
static int
vmm_ioport_reg_wakeup(struct vm *vm, struct ioport_reg_handler *regh, uint32_t *val)
{
	wakeup(regh->handler_arg);
	return (0);
}

/* call with ioregh->lock held */
static struct ioport_reg_handler *
vmm_ioport_find_handler(struct ioregh *ioregh, uint16_t port, uint16_t in,
		uint32_t mask_data, uint32_t data)
{
	struct ioport_reg_handler *regh;
	uint32_t mask;
	int i;

	regh = ioregh->handlers;
	for (i = 0; i < IOPORT_MAX_REG_HANDLER; i++) {
		if (regh[i].handler != NULL) {
			mask = regh[i].mask_data & mask_data;
			if ((regh[i].port == port) && (regh[i].in == in)
				&& ((mask & regh[i].data) == (mask & data))) {
				return &regh[i];
			}
		}
	}

	return (NULL);
}

/* call with ioregh->lock held */
static struct ioport_reg_handler *
vmm_ioport_empty_handler(struct ioregh *ioregh)
{
	struct ioport_reg_handler *regh;
	int i;

	regh = ioregh->handlers;
	for (i = 0; i < IOPORT_MAX_REG_HANDLER; i++) {
		if (regh[i].handler == NULL) {
			return &regh[i];
		}
	}

	return (NULL);
}


static int
vmm_ioport_add_handler(struct vm *vm, uint16_t port, uint16_t in, uint32_t mask_data,
	uint32_t data, ioport_reg_handler_func_t handler, void *handler_arg)
{
	struct ioport_reg_handler *regh;
	struct ioregh *ioregh;
	int ret = 0;

	ioregh = vm_ioregh(vm);

	sx_xlock(&ioregh->lock);

	regh = vmm_ioport_find_handler(ioregh, port, in, mask_data, data);
	if (regh != NULL) {
		printf("%s: handler for port %d in %d mask_data %d data %d \
				already registered\n",
				__FUNCTION__, port, in,  mask_data, data);
		ret = EEXIST;
		goto err;
	}

	regh = vmm_ioport_empty_handler(ioregh);
	if (regh == NULL) {
		printf("%s: empty reg_handler slot not found\n", __FUNCTION__);
		ret = ENOMEM;
		goto err;
	}

	regh->port = port;
	regh->in = in;
	regh->mask_data = mask_data;
	regh->data = data;
	regh->handler = handler;
	regh->handler_arg = handler_arg;

err:
	sx_xunlock(&ioregh->lock);
	return (ret);
}

static int
vmm_ioport_del_handler(struct vm *vm, uint16_t port, uint16_t in,
	uint32_t mask_data, uint32_t data)
{
	struct ioport_reg_handler *regh;
	struct ioregh *ioregh;
	int ret = 0;

	ioregh = vm_ioregh(vm);

	sx_xlock(&ioregh->lock);

	regh = vmm_ioport_find_handler(ioregh, port, in, mask_data, data);

	if (regh == NULL) {
		ret = EINVAL;
		goto err;
	}

	bzero(regh, sizeof(struct ioport_reg_handler));
err:
	sx_xunlock(&ioregh->lock);
	return (ret);
}

/*
 * register or delete a new I/O event handler.
 */
int
vmm_ioport_reg_handler(struct vm *vm, uint16_t port, uint16_t in,
	uint32_t mask_data, uint32_t data, enum vm_io_regh_type type, void *arg)
{
	int ret = 0;

	switch (type) {
	case VM_IO_REGH_DELETE:
		ret = vmm_ioport_del_handler(vm, port, in, mask_data, data);
		break;
	case VM_IO_REGH_KWEVENTS:
		ret = vmm_ioport_add_handler(vm, port, in, mask_data, data,
				vmm_ioport_reg_wakeup, arg);
		break;
	default:
		printf("%s: unknown reg_handler type\n", __FUNCTION__);
		ret = EINVAL;
		break;
	}

	return (ret);
}

/*
 * Invoke an handler, if the data matches.
 */
static int
invoke_reg_handler(struct vm *vm, int vcpuid, struct vm_exit *vmexit,
		   uint32_t *val, int *error)
{
	struct ioport_reg_handler *regh;
	struct ioregh *ioregh;
	uint32_t mask_data;

	mask_data = vie_size2mask(vmexit->u.inout.bytes);
	ioregh = vm_ioregh(vm);

	sx_slock(&ioregh->lock);
	regh = vmm_ioport_find_handler(ioregh, vmexit->u.inout.port,
			vmexit->u.inout.in, mask_data, vmexit->u.inout.eax);
	if (regh != NULL) {
		*error = (*(regh->handler))(vm, regh, val);
	}
	sx_sunlock(&ioregh->lock);
	return (regh != NULL);
}

struct ioregh *
ioregh_init(struct vm *vm)
{
	struct ioregh *ioregh;

	ioregh = malloc(sizeof(struct ioregh), M_IOREGH, M_WAITOK | M_ZERO);
	sx_init(&ioregh->lock, "ioregh lock");

	return (ioregh);
}

void
ioregh_cleanup(struct ioregh *ioregh)
{
	sx_destroy(&ioregh->lock);
	free(ioregh, M_IOREGH);
}
#else /* !VMM_IOPORT_REG_HANDLER */
#define invoke_reg_handler(_1, _2, _3, _4, _5) (0)
#endif /* VMM_IOPORT_REG_HANDLER */

static int
emulate_inout_port(struct vm *vm, int vcpuid, struct vm_exit *vmexit,
    bool *retu)
{
	ioport_handler_func_t handler;
	uint32_t mask, val;
	int regh = 0, error = 0;

	/*
	 * If there is no handler for the I/O port then punt to userspace.
	 */
	if ((vmexit->u.inout.port >= MAX_IOPORTS ||
	    (handler = ioport_handler[vmexit->u.inout.port]) == NULL) &&
	    (regh = invoke_reg_handler(vm, vcpuid, vmexit, &val, &error)) == 0) {
		*retu = true;
		return (0);
	}

	if (!regh) {
		mask = vie_size2mask(vmexit->u.inout.bytes);

		if (!vmexit->u.inout.in) {
			val = vmexit->u.inout.eax & mask;
		}

		error = (*handler)(vm, vcpuid, vmexit->u.inout.in,
			vmexit->u.inout.port, vmexit->u.inout.bytes, &val);
	}

	if (error) {
		/*
		 * The value returned by this function is also the return value
		 * of vm_run(). This needs to be a positive number otherwise it
		 * can be interpreted as a "pseudo-error" like ERESTART.
		 *
		 * Enforce this by mapping all errors to EIO.
		 */
		return (EIO);
	}

	if (vmexit->u.inout.in) {
		vmexit->u.inout.eax &= ~mask;
		vmexit->u.inout.eax |= val & mask;
		error = vm_set_register(vm, vcpuid, VM_REG_GUEST_RAX,
		    vmexit->u.inout.eax);
		KASSERT(error == 0, ("emulate_ioport: error %d setting guest "
		    "rax register", error));
	}
	*retu = false;
	return (0);
}

static int
emulate_inout_str(struct vm *vm, int vcpuid, struct vm_exit *vmexit, bool *retu)
{
	*retu = true;
	return (0);	/* Return to userspace to finish emulation */
}

int
vm_handle_inout(struct vm *vm, int vcpuid, struct vm_exit *vmexit, bool *retu)
{
	int bytes, error;

	bytes = vmexit->u.inout.bytes;
	KASSERT(bytes == 1 || bytes == 2 || bytes == 4,
	    ("vm_handle_inout: invalid operand size %d", bytes));

	if (vmexit->u.inout.string)
		error = emulate_inout_str(vm, vcpuid, vmexit, retu);
	else
		error = emulate_inout_port(vm, vcpuid, vmexit, retu);

	VCPU_CTR4(vm, vcpuid, "%s%s 0x%04x: %s",
	    vmexit->u.inout.rep ? "rep " : "",
	    inout_instruction(vmexit),
	    vmexit->u.inout.port,
	    error ? "error" : (*retu ? "userspace" : "handled"));

	return (error);
}
