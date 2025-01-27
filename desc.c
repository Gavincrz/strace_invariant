/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Copyright (c) 1999-2018 The strace developers.
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

#include <sys/socket.h>
#include "defs.h"
#include "xstring.h"

INV_FUNC(getpid)
{
    INV_FUNC_RET_ONLY(getpid)
}

INV_FUNC(getppid)
{
    INV_FUNC_RET_ONLY(getppid)
}

INV_FUNC(getgid)
{
    INV_FUNC_RET_ONLY(getgid)
}

INV_FUNC(getuid)
{
    INV_FUNC_RET_ONLY(getuid)
}

INV_FUNC(getegid)
{
    INV_FUNC_RET_ONLY(getegid)
}

INV_FUNC(geteuid)
{
    INV_FUNC_RET_ONLY(geteuid)
}

#define NUM_RET_CLOSE 1
INV_FUNC(close)
{

    static int *ibuf = NULL;
    static int vcount;
    static int num_ret = NUM_RET_CLOSE;

    if (tcp->flags & TCB_INV_TRACE){
        //
    }
    else if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){

        if (ibuf == NULL){
            vcount = read_fuzz_file(FUZZ_FILE(close), &ibuf, num_ret);
        }
        if (vcount >= 0 && count >= vcount){
            // read the original data
            kernel_long_t ret = tcp->u_rval;
            m_set mlist[NUM_RET_CLOSE] = {{&ret, sizeof(int), VARIABLE_NORMAL}};
            fuzzing_return_value(ibuf, mlist, num_ret);
            if (ret != tcp->u_rval){
                tprintf("\nmodified return: %ld count = %d\n", ret, count);
                tcp->ret_modified = 1;
            }
            // write back the value;
            tcp->u_rval = ret;
        }
    }
}

SYS_FUNC(close)
{
	printfd(tcp, tcp->u_arg[0]);
    using_ori_fd(tcp);
    if (tcp->flags & TCB_INV_TAMPER){
        remove_fd_entry(tcp->u_arg[0]);
    }
	return RVAL_DECODED;
}

SYS_FUNC(dup)
{
	printfd(tcp, tcp->u_arg[0]);
    using_ori_fd(tcp);
	return RVAL_DECODED | RVAL_FD;
}

static int
do_dup2(struct tcb *tcp, int flags_arg)
{
	printfd(tcp, tcp->u_arg[0]);
    using_ori_fd_idx(tcp, 0);
	tprints(", ");
	printfd(tcp, tcp->u_arg[1]);
    using_ori_fd_idx(tcp, 1);
	if (flags_arg >= 0) {
		tprints(", ");
		printflags(open_mode_flags, tcp->u_arg[flags_arg], "O_???");
	}

	return RVAL_DECODED | RVAL_FD;
}


INV_FUNC(dup2)
{
    INV_FUNC_RET_ONLY(dup2)
}

INV_FUNC(dup3)
{
    INV_FUNC_RET_ONLY(dup3)
}

SYS_FUNC(dup2)
{
	return do_dup2(tcp, -1);
}

SYS_FUNC(dup3)
{
	return do_dup2(tcp, 2);
}

static int
decode_select(struct tcb *const tcp, const kernel_ulong_t *const args,
	      void (*const print_tv_ts) (struct tcb *, kernel_ulong_t),
	      const char * (*const sprint_tv_ts) (struct tcb *, kernel_ulong_t))
{
	int i, j;
	int nfds, fdsize;
	fd_set *fds = NULL;
	const char *sep;
	kernel_ulong_t addr;

	/* Kernel truncates args[0] to int, we do the same. */
	nfds = (int) args[0];

	/* Kernel rejects negative nfds, so we don't parse it either. */
	if (nfds < 0)
		nfds = 0;

	/* Beware of select(2^31-1, NULL, NULL, NULL) and similar... */
	if (nfds > 1024*1024)
		nfds = 1024*1024;

	/*
	 * We had bugs a-la "while (j < args[0])" and "umoven(args[0])" below.
	 * Instead of args[0], use nfds for fd count, fdsize for array lengths.
	 */
	fdsize = (((nfds + 7) / 8) + current_wordsize-1) & -current_wordsize;

	if (entering(tcp)) {
		tprintf("%d", (int) args[0]);

		if (verbose(tcp) && fdsize > 0)
			fds = malloc(fdsize);
		for (i = 0; i < 3; i++) {
			addr = args[i+1];
			tprints(", ");
			if (!fds) {
				printaddr(addr);
				continue;
			}
			if (umoven_or_printaddr(tcp, addr, fdsize, fds))
				continue;
			tprints("[");
			for (j = 0, sep = "";; j++) {
				j = next_set_bit(fds, j, nfds);
				if (j < 0)
					break;
				tprints(sep);
				printfd(tcp, j);
				sep = " ";
			}
			tprints("]");
		}
		free(fds);
		tprints(", ");
		print_tv_ts(tcp, args[4]);
	} else {
		static char outstr[1024];
		char *outptr;
#define end_outstr (outstr + sizeof(outstr))
		int ready_fds;

		if (syserror(tcp))
			return 0;

		ready_fds = tcp->u_rval;
		if (ready_fds == 0) {
			tcp->auxstr = "Timeout";
			return RVAL_STR;
		}

		fds = malloc(fdsize);

		outptr = outstr;
		sep = "";
		for (i = 0; i < 3 && ready_fds > 0; i++) {
			int first = 1;

			addr = args[i+1];
			if (!addr || !fds || umoven(tcp, addr, fdsize, fds) < 0)
				continue;
			for (j = 0;; j++) {
				j = next_set_bit(fds, j, nfds);
				if (j < 0)
					break;
				/* +2 chars needed at the end: ']',NUL */
				if (outptr < end_outstr - (sizeof(", except [") + sizeof(int)*3 + 2)) {
					if (first) {
						outptr = xappendstr(outstr,
							outptr,
							"%s%s [%u",
							sep,
							i == 0 ? "in" : i == 1 ? "out" : "except",
							j
						);
						first = 0;
						sep = ", ";
					} else {
						outptr = xappendstr(outstr,
							outptr,
							" %u", j);
					}
				}
				if (--ready_fds == 0)
					break;
			}
			if (outptr != outstr)
				*outptr++ = ']';
		}
		free(fds);
		/* This contains no useful information on SunOS.  */
		if (args[4]) {
			const char *str = sprint_tv_ts(tcp, args[4]);
			if (outptr + sizeof("left ") + strlen(sep) + strlen(str) < end_outstr) {
				outptr = xappendstr(outstr, outptr,
						    "%sleft %s", sep, str);
			}
		}
		*outptr = '\0';
		tcp->auxstr = outstr;
		return RVAL_STR;
#undef end_outstr
	}
	return 0;
}

#if HAVE_ARCH_OLD_SELECT
SYS_FUNC(oldselect)
{
	kernel_ulong_t *args =
		fetch_indirect_syscall_args(tcp, tcp->u_arg[0], 5);

	if (args) {
		return decode_select(tcp, args, print_timeval, sprint_timeval);
	} else {
		if (entering(tcp))
			printaddr(tcp->u_arg[0]);
		return RVAL_DECODED;
	}
}
#endif /* HAVE_ARCH_OLD_SELECT */

#ifdef ALPHA
SYS_FUNC(osf_select)
{
	return decode_select(tcp, tcp->u_arg, print_timeval32, sprint_timeval32);
}
#endif

#define NUM_RET_SELECT 5
INV_FUNC(select)
{
	static int *ibuf = NULL;
	static int vcount;
	static int num_ret = NUM_RET_SELECT;
	if (tcp->flags & TCB_INV_TRACE){
		//TODO: print trace
	}
	else if (tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
		if (ibuf == NULL){
			vcount = read_fuzz_file(FUZZ_FILE(select), &ibuf, num_ret);
		}
		if (vcount >= 0 && count >= vcount){
			kernel_long_t ret = tcp->u_rval;
			size_t fd_size = sizeof(fd_set);

			fd_set *readfds = (fd_set*)malloc(fd_size);
			fd_set *writefds = (fd_set*)malloc(fd_size);
			fd_set *exceptfds = (fd_set*)malloc(fd_size);
			struct timeval *timeout = (struct timeval*)malloc(sizeof(struct timeval));

			tfetch_mem(tcp, tcp->u_arg[1], fd_size, readfds);
			tfetch_mem(tcp, tcp->u_arg[2], fd_size, writefds);
			tfetch_mem(tcp, tcp->u_arg[3], fd_size, exceptfds);
			tfetch_mem(tcp, tcp->u_arg[4], sizeof(struct timeval), timeout);

			/* tamper code accept */
			m_set mlist[NUM_RET_SELECT] = {{readfds, fd_size, VARIABLE_NORMAL},\
										{writefds, fd_size, VARIABLE_NORMAL},\
										{exceptfds, fd_size, VARIABLE_NORMAL},\
										{timeout, sizeof(struct timeval), VARIABLE_NORMAL},\
                                        {&ret, sizeof(int), VARIABLE_FD}};
			fuzzing_return_value(ibuf, mlist, num_ret);

			if (ibuf[4] == 1){
				tprintf("\nmodified return: %ld \n", ret);
				tcp->ret_modified = 1;
			}


			/* end of temper code accept */
			/* write back data to tracee and clean up */
			vm_write_mem(tcp->pid, readfds, tcp->u_arg[1], fd_size);
			vm_write_mem(tcp->pid, writefds, tcp->u_arg[2], fd_size);
			vm_write_mem(tcp->pid, exceptfds, tcp->u_arg[3], fd_size);
			vm_write_mem(tcp->pid, timeout, tcp->u_arg[4], sizeof(struct timeval));
			tcp->u_rval = ret;

			free(readfds);
			free(writefds);
			free(exceptfds);
			free(timeout);
		}


	}
}

SYS_FUNC(select)
{
	return decode_select(tcp, tcp->u_arg, print_timeval, sprint_timeval);
}

static int
umove_kulong_array_or_printaddr(struct tcb *const tcp, const kernel_ulong_t addr,
				kernel_ulong_t *const ptr, const size_t n)
{
#ifndef current_klongsize
	if (current_klongsize < sizeof(*ptr)) {
		uint32_t ptr32[n];
		int r = umove_or_printaddr(tcp, addr, &ptr32);
		if (!r) {
			size_t i;

			for (i = 0; i < n; ++i)
				ptr[i] = ptr32[i];
		}
		return r;
	}
#endif /* !current_klongsize */
	return umoven_or_printaddr(tcp, addr, n * sizeof(*ptr), ptr);
}


#define NUM_RET_PSELECT6 4
INV_FUNC(pselect6)
{
	static int *ibuf = NULL;
	static int vcount;
	static int num_ret = NUM_RET_PSELECT6;
	if (tcp->flags & TCB_INV_TRACE){
		//TODO: print trace
	}
	else if (tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
		if (ibuf == NULL){
			vcount = read_fuzz_file(FUZZ_FILE(pselect6), &ibuf, num_ret);
		}
		if (vcount >= 0 && count >= vcount){
			kernel_long_t ret = tcp->u_rval;
			size_t fd_size = sizeof(fd_set);

			fd_set *readfds = (fd_set*)malloc(fd_size);
			fd_set *writefds = (fd_set*)malloc(fd_size);
			fd_set *exceptfds = (fd_set*)malloc(fd_size);

			tfetch_mem(tcp, tcp->u_arg[1], fd_size, readfds);
			tfetch_mem(tcp, tcp->u_arg[2], fd_size, writefds);
			tfetch_mem(tcp, tcp->u_arg[3], fd_size, exceptfds);

			/* tamper code accept */
			m_set mlist[NUM_RET_PSELECT6] = {{readfds, fd_size, VARIABLE_NORMAL},\
										{writefds, fd_size, VARIABLE_NORMAL},\
										{exceptfds, fd_size, VARIABLE_NORMAL},\
                                        {&ret, sizeof(int), VARIABLE_FD}};
			fuzzing_return_value(ibuf, mlist, num_ret);

			if (ibuf[3] == 1){
				tprintf("\nmodified return: %ld \n", ret);
				tcp->ret_modified = 1;
			}


			/* end of temper code accept */
			/* write back data to tracee and clean up */
			vm_write_mem(tcp->pid, readfds, tcp->u_arg[1], fd_size);
			vm_write_mem(tcp->pid, writefds, tcp->u_arg[2], fd_size);
			vm_write_mem(tcp->pid, exceptfds, tcp->u_arg[3], fd_size);
			tcp->u_rval = ret;

			free(readfds);
			free(writefds);
			free(exceptfds);
		}


	}
}

SYS_FUNC(pselect6)
{
	int rc = decode_select(tcp, tcp->u_arg, print_timespec, sprint_timespec);
	if (entering(tcp)) {
		kernel_ulong_t data[2];

		tprints(", ");
		if (!umove_kulong_array_or_printaddr(tcp, tcp->u_arg[5],
						     data, ARRAY_SIZE(data))) {
			tprints("{");
			/* NB: kernel requires data[1] == NSIG_BYTES */
			print_sigset_addr_len(tcp, data[0], data[1]);
			tprintf(", %" PRI_klu "}", data[1]);
		}
	}

	return rc;
}
