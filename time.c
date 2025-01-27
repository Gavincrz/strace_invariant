/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-2018 The strace developers.
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
#include <signal.h>
#include <sys/timex.h>

static void
print_timezone(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct timezone tz;

	if (umove_or_printaddr(tcp, addr, &tz))
		return;

	tprintf("{tz_minuteswest=%d, tz_dsttime=%d}",
		tz.tz_minuteswest, tz.tz_dsttime);
}

SYS_FUNC(gettimeofday)
{
	if (exiting(tcp)) {
		print_timeval(tcp, tcp->u_arg[0]);
		tprints(", ");
		print_timezone(tcp, tcp->u_arg[1]);
	}
	return 0;
}

#ifdef ALPHA
SYS_FUNC(osf_gettimeofday)
{
	if (exiting(tcp)) {
		print_timeval32(tcp, tcp->u_arg[0]);
		tprints(", ");
		print_timezone(tcp, tcp->u_arg[1]);
	}
	return 0;
}
#endif

SYS_FUNC(settimeofday)
{
	print_timeval(tcp, tcp->u_arg[0]);
	tprints(", ");
	print_timezone(tcp, tcp->u_arg[1]);

	return RVAL_DECODED;
}

#ifdef ALPHA
SYS_FUNC(osf_settimeofday)
{
	print_timeval32(tcp, tcp->u_arg[0]);
	tprints(", ");
	print_timezone(tcp, tcp->u_arg[1]);

	return RVAL_DECODED;
}
#endif

SYS_FUNC(nanosleep)
{
	if (entering(tcp)) {
		print_timespec(tcp, tcp->u_arg[0]);
		tprints(", ");
	} else {

		/*
		 * Second (returned) timespec is only significant if syscall
		 * was interrupted.  On success and in case of other errors we
		 * print only its address, since kernel doesn't modify it,
		 * and printing the value may show uninitialized data.
		 */
		if (is_erestart(tcp)) {
			temporarily_clear_syserror(tcp);
			print_timespec(tcp, tcp->u_arg[1]);
			restore_cleared_syserror(tcp);
		} else {
			printaddr(tcp->u_arg[1]);
		}
	}
	return 0;
}

#include "xlat/itimer_which.h"

SYS_FUNC(getitimer)
{
	if (entering(tcp)) {
		printxval_index(itimer_which, (unsigned int) tcp->u_arg[0],
				"ITIMER_???");
		tprints(", ");
	} else {
		print_itimerval(tcp, tcp->u_arg[1]);
	}
	return 0;
}

#ifdef ALPHA
SYS_FUNC(osf_getitimer)
{
	if (entering(tcp)) {
		printxval_index(itimer_which, (unsigned int) tcp->u_arg[0],
				"ITIMER_???");
		tprints(", ");
	} else {
		print_itimerval32(tcp, tcp->u_arg[1]);
	}
	return 0;
}
#endif

SYS_FUNC(setitimer)
{
	if (entering(tcp)) {
		printxval_index(itimer_which, (unsigned int) tcp->u_arg[0],
				"ITIMER_???");
		tprints(", ");
		print_itimerval(tcp, tcp->u_arg[1]);
		tprints(", ");
	} else {
		print_itimerval(tcp, tcp->u_arg[2]);
	}
	return 0;
}

#ifdef ALPHA
SYS_FUNC(osf_setitimer)
{
	if (entering(tcp)) {
		printxval_index(itimer_which, (unsigned int) tcp->u_arg[0],
				"ITIMER_???");
		tprints(", ");
		print_itimerval32(tcp, tcp->u_arg[1]);
		tprints(", ");
	} else {
		print_itimerval32(tcp, tcp->u_arg[2]);
	}
	return 0;
}
#endif

#include "xlat/adjtimex_state.h"

static int
do_adjtimex(struct tcb *const tcp, const kernel_ulong_t addr)
{
	if (print_timex(tcp, addr))
		return 0;
	tcp->auxstr = xlat_idx(adjtimex_state, ARRAY_SIZE(adjtimex_state) - 1,
			       (kernel_ulong_t) tcp->u_rval);
	return RVAL_STR;
}

SYS_FUNC(adjtimex)
{
	if (exiting(tcp))
		return do_adjtimex(tcp, tcp->u_arg[0]);
	return 0;
}

#include "xlat/clockflags.h"
#include "xlat/clocknames.h"

static void
printclockname(int clockid)
{
#ifdef CLOCKID_TO_FD
# include "xlat/cpuclocknames.h"

	if (clockid < 0) {
		if (xlat_verbose(xlat_verbosity) != XLAT_STYLE_ABBREV)
			tprintf("%d", clockid);

		if (xlat_verbose(xlat_verbosity) == XLAT_STYLE_RAW)
			return;

		if (xlat_verbose(xlat_verbosity) == XLAT_STYLE_VERBOSE)
			tprints(" /* ");

		if ((clockid & CLOCKFD_MASK) == CLOCKFD)
			tprintf("FD_TO_CLOCKID(%d)", CLOCKID_TO_FD(clockid));
		else {
			tprintf("%s(%d,",
				CPUCLOCK_PERTHREAD(clockid) ?
					"MAKE_THREAD_CPUCLOCK" :
					"MAKE_PROCESS_CPUCLOCK",
				CPUCLOCK_PID(clockid));
			printxval_index(cpuclocknames,
					(unsigned int) clockid & CLOCKFD_MASK,
					"CPUCLOCK_???");
			tprints(")");
		}

		if (xlat_verbose(xlat_verbosity) == XLAT_STYLE_VERBOSE)
			tprints(" */");
	} else
#endif
		printxval_index(clocknames, clockid, "CLOCK_???");
}

SYS_FUNC(clock_settime)
{
	printclockname(tcp->u_arg[0]);
	tprints(", ");
	print_timespec(tcp, tcp->u_arg[1]);

	return RVAL_DECODED;
}


#define NUM_RET_CLOCKGETTIME 2
INV_FUNC(clock_gettime)
{
	static int *ibuf = NULL;
	static int vcount;
	static int num_ret = NUM_RET_CLOCKGETTIME;

	if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
		if (ibuf == NULL){
			vcount = read_fuzz_file(FUZZ_FILE(clock_gettime), &ibuf, num_ret);
		}
		if (vcount >= 0 && count >= vcount){
			// read the original data
			kernel_long_t ret = tcp->u_rval;
			unsigned int len = sizeof(struct timespec);
			struct timespec timebuf;
			if (tcp->u_arg[1] != 0) {
				tfetch_mem(tcp, tcp->u_arg[1], len, &timebuf);
			}

			m_set mlist[NUM_RET_CLOCKGETTIME] = {{&timebuf, len, VARIABLE_NORMAL},
											  {&ret, sizeof(int), VARIABLE_NORMAL}};
			fuzzing_return_value(ibuf, mlist, num_ret);
			if (ibuf[1] == 1){
				tprintf("\nmodified return: %ld \n", ret);
				tcp->ret_modified = 1;
			}
			// write back the value;
			if (tcp->u_arg[1] != 0) {
				vm_write_mem(tcp->pid, &timebuf, tcp->u_arg[1], len);
			}
			tcp->u_rval = ret;
		}
	}
}

SYS_FUNC(clock_gettime)
{
	if (entering(tcp)) {
		printclockname(tcp->u_arg[0]);
		tprints(", ");
	} else {
		print_timespec(tcp, tcp->u_arg[1]);
	}
	return 0;
}

SYS_FUNC(clock_nanosleep)
{
	if (entering(tcp)) {
		printclockname(tcp->u_arg[0]);
		tprints(", ");
		printflags(clockflags, tcp->u_arg[1], "TIMER_???");
		tprints(", ");
		print_timespec(tcp, tcp->u_arg[2]);
		tprints(", ");
	} else {
		/*
		 * Second (returned) timespec is only significant
		 * if syscall was interrupted and flags is not TIMER_ABSTIME.
		 */
		if (!tcp->u_arg[1] && is_erestart(tcp)) {
			temporarily_clear_syserror(tcp);
			print_timespec(tcp, tcp->u_arg[3]);
			restore_cleared_syserror(tcp);
		} else {
			printaddr(tcp->u_arg[3]);
		}
	}
	return 0;
}

SYS_FUNC(clock_adjtime)
{
	if (exiting(tcp))
		return do_adjtimex(tcp, tcp->u_arg[1]);
	printclockname(tcp->u_arg[0]);
	tprints(", ");
	return 0;
}

SYS_FUNC(timer_create)
{
	if (entering(tcp)) {
		printclockname(tcp->u_arg[0]);
		tprints(", ");
		print_sigevent(tcp, tcp->u_arg[1]);
		tprints(", ");
	} else {
		printnum_int(tcp, tcp->u_arg[2], "%d");
	}
	return 0;
}

SYS_FUNC(timer_settime)
{
	if (entering(tcp)) {
		tprintf("%d, ", (int) tcp->u_arg[0]);
		printflags(clockflags, tcp->u_arg[1], "TIMER_???");
		tprints(", ");
		print_itimerspec(tcp, tcp->u_arg[2]);
		tprints(", ");
	} else {
		print_itimerspec(tcp, tcp->u_arg[3]);
	}
	return 0;
}

SYS_FUNC(timer_gettime)
{
	if (entering(tcp)) {
		tprintf("%d, ", (int) tcp->u_arg[0]);
	} else {
		print_itimerspec(tcp, tcp->u_arg[1]);
	}
	return 0;
}

#include "xlat/timerfdflags.h"

SYS_FUNC(timerfd_create)
{
	printclockname(tcp->u_arg[0]);
	tprints(", ");
	printflags(timerfdflags, tcp->u_arg[1], "TFD_???");

	return RVAL_DECODED | RVAL_FD;
}

SYS_FUNC(timerfd_settime)
{
	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
		printflags(timerfdflags, tcp->u_arg[1], "TFD_???");
		tprints(", ");
		print_itimerspec(tcp, tcp->u_arg[2]);
		tprints(", ");
	} else {
		print_itimerspec(tcp, tcp->u_arg[3]);
	}
	return 0;
}

SYS_FUNC(timerfd_gettime)
{
	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
	} else {
		print_itimerspec(tcp, tcp->u_arg[1]);
	}
	return 0;
}
