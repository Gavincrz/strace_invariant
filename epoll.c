/*
 * Copyright (c) 2004-2007 Ulrich Drepper <drepper@redhat.com>
 * Copyright (c) 2004 Roland McGrath <roland@redhat.com>
 * Copyright (c) 2005-2015 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2015-2018 The strace developers.
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "defs.h"
#include <fcntl.h>
#include <sys/epoll.h>

SYS_FUNC(epoll_create)
{
	tprintf("%d", (int) tcp->u_arg[0]);

	return RVAL_DECODED | RVAL_FD;
}

#include "xlat/epollflags.h"

SYS_FUNC(epoll_create1)
{
	printflags(epollflags, tcp->u_arg[0], "EPOLL_???");

	return RVAL_DECODED | RVAL_FD;
}

#include "xlat/epollevents.h"

static bool
print_epoll_event(struct tcb *tcp, void *elem_buf, size_t elem_size, void *data)
{
	const struct epoll_event *ev = elem_buf;

	tprints("{");
	printflags(epollevents, ev->events, "EPOLL???");
	/* We cannot know what format the program uses, so print u32 and u64
	   which will cover every value.  */
	tprintf(", {u32=%" PRIu32 ", u64=%" PRIu64 "}}",
		ev->data.u32, ev->data.u64);

	return true;
}

#include "xlat/epollctls.h"

SYS_FUNC(epoll_ctl)
{
	printfd(tcp, tcp->u_arg[0]);
	tprints(", ");
	const unsigned int op = tcp->u_arg[1];
	printxval(epollctls, op, "EPOLL_CTL_???");
	tprints(", ");
	printfd(tcp, tcp->u_arg[2]);
	tprints(", ");
	struct epoll_event ev;
	if (EPOLL_CTL_DEL == op)
		printaddr(tcp->u_arg[3]);
	else if (!umove_or_printaddr(tcp, tcp->u_arg[3], &ev))
		print_epoll_event(tcp, &ev, sizeof(ev), 0);

	return RVAL_DECODED;
}

void print_arg_trace_epoll_wait(struct tcb *tcp){
    printinvvar("epfd", PRINT_LD, tcp->u_arg[0]);
    printinvvar("events", PRINT_ADDR, tcp->u_arg[1]);
    int nelem;
    if (entering(tcp)){
        nelem = 0;
    }
    else{
        nelem = tcp->u_rval;
    }
    // events[...]
    invprints("events[..]\n");
    if (nelem == 0){
        invprints("nonsensical\n2\n");
    }
    else{
        kernel_ulong_t cur_addr = tcp->u_arg[1];
        invprints("[");
        for (int i = 0; i < nelem; i++){
            printaddrinv(cur_addr);
            cur_addr += sizeof(struct epoll_event);
            if (i < nelem - 1){
                invprints(", ");
            }
        }
        invprints("]\n1\n");
    }

    unsigned int total_size = sizeof(struct epoll_event) * nelem;
    struct epoll_event *ev_buf = malloc(total_size);
    tfetch_mem(tcp, tcp->u_arg[1], total_size, ev_buf);
    // events[...].events
    invprints("events[..].events\n");
    if (nelem == 0){
        invprints("nonsensical\n2\n");
    }
    else{
        invprints("[");
        for (int i = 0; i < nelem; i++){
            printluinv(ev_buf[i].events);
            if (i < nelem - 1){
                invprints(", ");
            }
        }
        invprints("]\n1\n");
    }

    // events[...].data
    invprints("events[..].data.u64\n");
    if (nelem == 0){
        invprints("nonsensical\n2\n");
    }
    else{
        invprints("[");
        for (int i = 0; i < nelem; i++){
            printldinv(ev_buf[i].data.u64);
            if (i < nelem - 1){
                invprints(", ");
            }
        }
        invprints("]\n1\n");
    }
    free(ev_buf);
    //maxevents
    printinvvar("maxevents", PRINT_LD, tcp->u_arg[2]);
    //timeout
    printinvvar("timeout", PRINT_LD, tcp->u_arg[3]);

}

enum handler_t {
    HANDLER_UNSET,
    HANDLER_GO_ON,
    HANDLER_FINISHED,
    HANDLER_COMEBACK,
    HANDLER_WAIT_FOR_EVENT,
    HANDLER_ERROR,
    HANDLER_WAIT_FOR_FD
};
typedef enum handler_t handler_t;

typedef handler_t (*fdevent_handler)();
typedef struct _fdnode {
    fdevent_handler handler;
    void *ctx;
    void *handler_ctx;
    int fd;
    int events;
} fdnode;

#define NUM_RET_EPOLL_WAIT 2
INV_FUNC(epoll_wait)
{
    static int *ibuf = NULL;
    static int vcount;
    static int num_ret = NUM_RET_EPOLL_WAIT;
    if (tcp->flags & TCB_INV_TRACE){
        if (entering(tcp)) {
            invprints("\n");
            invprints(ENTER_HEADER(epoll_wait));
            invprintf("%d\n", count);
            print_arg_trace_epoll_wait(tcp);
        } else {
            invprints("\n");
            invprints(EXIT_HEADER(epoll_wait));
            invprintf("%d\n", count);
            print_arg_trace_epoll_wait(tcp);
            printinvvar("return", PRINT_LD, tcp->u_rval);
        }
    }
    else if (tcp->flags & TCB_INV_TAMPER && !entering(tcp)){

        if (ibuf == NULL){
            vcount = read_fuzz_file(FUZZ_FILE(epoll_wait), &ibuf, num_ret);
        }
        if (count >= vcount){
            /* read data from tracee */
            kernel_long_t maxevents = tcp->u_arg[2];
            kernel_long_t ret = tcp->u_rval;
            unsigned int len = sizeof(struct epoll_event) * maxevents;
            struct epoll_event *events = malloc(len);
            tfetch_mem(tcp, tcp->u_arg[1], len, events);
            /* tamper code epoll_wait */

            m_set mlist[NUM_RET_EPOLL_WAIT] = {{events, len, VARIABLE_NORMAL},\
                                        {&ret, sizeof(int), VARIABLE_NORMAL}};
            fuzzing_return_value(ibuf, mlist, num_ret);
            tprintf("\nmodified return: %ld \n", ret);

//		    ret = 1;
//		    events->data.fd = 4100;
//
//		    fdnode node;
//		    node.fd = 4100;
//		    node.handler = 0x4092ac;
//
//		    struct epoll_event *child_event_addr =  (struct epoll_event *)tcp->u_arg[1];
//
//		    memcpy(&(events[2]), &node, sizeof(node));
//		    events[1].data.ptr = &(child_event_addr[2]);


            /* end of temper code epoll_wait */
            /* write back data to tracee and clean up */
            vm_write_mem(tcp->pid, events, tcp->u_arg[1], len);
            tcp->u_rval = ret;
            free(events);
        }


    }

	return;
}

static void
epoll_wait_common(struct tcb *tcp)
{
	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
	} else {
		struct epoll_event ev;
		print_array(tcp, tcp->u_arg[1], tcp->u_rval, &ev, sizeof(ev),
			    tfetch_mem, print_epoll_event, 0);
		tprintf(", %d, %d", (int) tcp->u_arg[2], (int) tcp->u_arg[3]);
	}
}

SYS_FUNC(epoll_wait)
{
	epoll_wait_common(tcp);
	return 0;
}

SYS_FUNC(epoll_pwait)
{
	epoll_wait_common(tcp);
	if (exiting(tcp)) {
		tprints(", ");
		/* NB: kernel requires arg[5] == NSIG_BYTES */
		print_sigset_addr_len(tcp, tcp->u_arg[4], tcp->u_arg[5]);
		tprintf(", %" PRI_klu, tcp->u_arg[5]);
	}
	return 0;
}
