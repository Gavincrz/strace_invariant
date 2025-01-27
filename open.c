/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Copyright (c) 2005-2007 Roland McGrath <roland@redhat.com>
 * Copyright (c) 2006-2007 Ulrich Drepper <drepper@redhat.com>
 * Copyright (c) 2009-2013 Denys Vlasenko <dvlasenk@redhat.com>
 * Copyright (c) 2005-2015 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2014-2018 The strace developers.
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
#include "xstring.h"

#include <asm/fcntl.h>

/* some libcs are guilty of messing up with O_ACCMODE */
#undef O_ACCMODE
#define O_ACCMODE 03

#ifdef O_LARGEFILE
# if O_LARGEFILE == 0		/* biarch platforms in 64-bit mode */
#  undef O_LARGEFILE
# endif
#endif

#include "xlat/open_access_modes.h"
#include "xlat/open_mode_flags.h"

#ifndef AT_FDCWD
# define AT_FDCWD	-100
#endif

/* The fd is an "int", so when decoding x86 on x86_64, we need to force sign
 * extension to get the right value.  We do this by declaring fd as int here.
 */
void
print_dirfd(struct tcb *tcp, int fd)
{
	if (fd == AT_FDCWD)
		print_xlat_d(AT_FDCWD);
	else
		printfd(tcp, fd);

	tprints(", ");
}

/*
 * low bits of the open(2) flags define access mode,
 * other bits are real flags.
 */
const char *
sprint_open_modes(unsigned int flags)
{
	static char outstr[(1 + ARRAY_SIZE(open_mode_flags)) * sizeof("O_LARGEFILE")];
	char *p;
	char sep;
	const char *str;
	const struct xlat *x;

	sep = ' ';
	p = stpcpy(outstr, "flags");
	str = xlookup(open_access_modes, flags & 3);
	if (str) {
		*p++ = sep;
		p = stpcpy(p, str);
		flags &= ~3;
		if (!flags)
			return outstr;
		sep = '|';
	}

	for (x = open_mode_flags; x->str; x++) {
		if ((flags & x->val) == x->val) {
			*p++ = sep;
			p = stpcpy(p, x->str);
			flags &= ~x->val;
			if (!flags)
				return outstr;
			sep = '|';
		}
	}
	/* flags is still nonzero */
	*p++ = sep;
	p = xappendstr(outstr, p, "%#x", flags);
	return outstr;
}

void
tprint_open_modes(unsigned int flags)
{
	print_xlat_ex(flags, sprint_open_modes(flags) + sizeof("flags"),
		      XLAT_STYLE_DEFAULT);
}

void print_arg_trace_open(struct tcb * tcp)
{
    printpathinv("pathname", tcp, tcp->u_arg[0]);
    printinvvar("flags", PRINT_LD, tcp->u_arg[1]);
}

#define NUM_RET_OPEN 1
INV_FUNC(open)
{
    static int *ibuf = NULL;
    static int vcount;
    static int num_ret = NUM_RET_OPEN;
	if (tcp->flags & TCB_INV_TRACE){
		if (entering(tcp)) {
			invprints("\n");
			invprints(ENTER_HEADER(open));
			invprintf("%d\n", count);
            print_arg_trace_open(tcp);
		} else {
			invprints("\n");
			invprints(EXIT_HEADER(open));
			invprintf("%d\n", count);
            print_arg_trace_open(tcp);
			printinvvar("return", PRINT_LD, tcp->u_rval);
		}
	}
	else if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
        if (ibuf == NULL){
            vcount = read_fuzz_file(FUZZ_FILE(open), &ibuf, num_ret);
        }
        if (vcount >= 0 && count >= vcount){
            kernel_long_t ret = tcp->u_rval;
            m_set mlist[NUM_RET_OPEN] = {{&ret, sizeof(int), VARIABLE_FD}};
            fuzzing_return_value(ibuf, mlist, num_ret);

            if (ibuf[0] == 1){
                tprintf("\nmodified return: %ld \n", ret);
                tcp->ret_modified = 1;
            }

			tcp->u_rval = ret;
        }
	}
}

static int
decode_open(struct tcb *tcp, int offset)
{
	printpath(tcp, tcp->u_arg[offset]);
	tprints(", ");
	/* flags */
	tprint_open_modes(tcp->u_arg[offset + 1]);
	if (tcp->u_arg[offset + 1] & (O_CREAT | __O_TMPFILE)) {
		/* mode */
		tprints(", ");
		print_numeric_umode_t(tcp->u_arg[offset + 2]);
	}

	return RVAL_DECODED | RVAL_FD;
}

SYS_FUNC(open)
{
	return decode_open(tcp, 0);
}


#define NUM_RET_OPENAT 1
INV_FUNC(openat)
{
    static int *ibuf = NULL;
    static int vcount;
    static int num_ret = NUM_RET_OPENAT;
    if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
        if (ibuf == NULL){
            vcount = read_fuzz_file(FUZZ_FILE(openat), &ibuf, num_ret);
        }
        if (vcount >= 0 && count >= vcount){
            kernel_long_t ret = tcp->u_rval;
            m_set mlist[NUM_RET_OPENAT] = {{&ret, sizeof(int), VARIABLE_FD}};
            fuzzing_return_value(ibuf, mlist, num_ret);

            if (ibuf[0] == 1){
                tprintf("\nmodified return: %ld \n", ret);
                tcp->ret_modified = 1;
            }

            tcp->u_rval = ret;
        }
    }
}


SYS_FUNC(openat)
{
	print_dirfd(tcp, tcp->u_arg[0]);
	return decode_open(tcp, 1);
}

SYS_FUNC(creat)
{
	printpath(tcp, tcp->u_arg[0]);
	tprints(", ");
	print_numeric_umode_t(tcp->u_arg[1]);

	return RVAL_DECODED | RVAL_FD;
}
