/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * Copyright (c) 2005-2015 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2014-2017 The strace developers.
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
#define _GNU_SOURCE
#include "defs.h"

#include <dirent.h>     /* Defines DT_* constants */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

#include DEF_MPERS_TYPE(kernel_dirent)

#include MPERS_DEFS

#define D_NAME_LEN_MAX 256

static void
print_old_dirent(struct tcb *const tcp, const kernel_ulong_t addr)
{
	kernel_dirent d;

	if (umove_or_printaddr(tcp, addr, &d))
		return;

	tprintf("{d_ino=%llu, d_off=%llu, d_reclen=%u, d_name=",
		zero_extend_signed_to_ull(d.d_ino),
		zero_extend_signed_to_ull(d.d_off), d.d_reclen);
	if (d.d_reclen > D_NAME_LEN_MAX)
		d.d_reclen = D_NAME_LEN_MAX;
	printpathn(tcp, addr + offsetof(kernel_dirent, d_name), d.d_reclen);
	tprints("}");
}

SYS_FUNC(readdir)
{
	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
	} else {
		if (tcp->u_rval == 0)
			printaddr(tcp->u_arg[1]);
		else
			print_old_dirent(tcp, tcp->u_arg[1]);
		/* Not much point in printing this out, it is always 1. */
		if (tcp->u_arg[2] != 1)
			tprintf(", %" PRI_klu, tcp->u_arg[2]);
	}
	return 0;
}

#define NUM_RET_GETDENTS 4
FUZZ_FUNC(getdents)
{
    // pick one value to modify
    int ret_index = rand() % NUM_RET_GETDENTS;

    // read the original data
    unsigned int len = sizeof(char) * tcp->u_arg[2];
    void* buf = malloc(len);
    umoven(tcp, tcp->u_arg[1], len, buf);
    kernel_long_t ret = tcp->u_rval;
    struct linux_dirent *d = (struct linux_dirent *) (buf);

    r_set rlist[NUM_RET_GETDENTS] = {{&ret, sizeof(int), "ret", 0, 0},
                                  {&(d->d_off), sizeof(d->d_off), "d_off", 0, 0},
                                  {&(d->d_reclen), sizeof(d->d_reclen), "d_reclen", 0, 0},
                                  {&(d->d_type), sizeof(d->d_type), "d_type", 0, 0}};
    COMMON_FUZZ

    // write back the value;
    tcp->u_rval = ret;
    vm_write_mem(tcp->pid, buf, tcp->u_arg[1], len);
    free(buf);

    // modify return value
    if (ret_index == 0) {
        tcp->ret_modified = 1;
    }
}

#undef NUM_RET_GETDENTS
#define  NUM_RET_GETDENTS 2
INV_FUNC(getdents)
{
	static int *ibuf = NULL;
	static int vcount;
	static int num_ret = NUM_RET_GETDENTS;

	if (tcp->flags & TCB_INV_TRACE){
		//TODO:
	}
	else if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){

		if (ibuf == NULL){
			vcount = read_fuzz_file(FUZZ_FILE(getdents), &ibuf, num_ret);
		}
		if (vcount >= 0 && count >= vcount){
			// read the original data
			unsigned int len = sizeof(char) * tcp->u_arg[2];
			void* buf = malloc(len);
			tfetch_mem(tcp, tcp->u_arg[1], len, buf);
			kernel_long_t ret = tcp->u_rval;

			m_set mlist[NUM_RET_GETDENTS] = {{buf, len, VARIABLE_NORMAL},\
                                        {&ret, sizeof(int), VARIABLE_NORMAL}};
			fuzzing_return_value(ibuf, mlist, num_ret);
			if (ibuf[1] == 1){
				tprintf("\nmodified return: %ld \n", ret);
				tcp->ret_modified = 1;
			}
			// write back the value;
			tcp->u_rval = ret;
			vm_write_mem(tcp->pid, buf, tcp->u_arg[1], len);
			free(buf);
		}

	}
}

SYS_FUNC(getdents)
{
	unsigned int i, len, dents = 0;
	unsigned char *buf;

	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		return 0;
	}

	const unsigned int count = tcp->u_arg[2];

	if (syserror(tcp) || !verbose(tcp)) {
		tprints(", ");
		printaddr(tcp->u_arg[1]);
		tprintf(", %u", count);
		return 0;
	}

	/* Beware of insanely large or too small values in tcp->u_rval */
	if (tcp->u_rval > 1024*1024)
		len = 1024*1024;
	else if (tcp->u_rval < (int) sizeof(kernel_dirent))
		len = 0;
	else
		len = tcp->u_rval;

	if (len) {
		buf = malloc(len);
		if (!buf || umoven(tcp, tcp->u_arg[1], len, buf) < 0) {
			tprints(", ");
			printaddr(tcp->u_arg[1]);
			tprintf(", %u", count);
			free(buf);
			return 0;
		}
	} else {
		buf = NULL;
	}

	tprints(",");
	if (!abbrev(tcp))
		tprints(" [");
	for (i = 0; len && i <= len - sizeof(kernel_dirent); ) {
		kernel_dirent *d = (kernel_dirent *) &buf[i];

		if (!abbrev(tcp)) {
			int oob = d->d_reclen < sizeof(kernel_dirent) ||
				  i + d->d_reclen - 1 >= len;
			int d_name_len = oob ? len - i : d->d_reclen;
			d_name_len -= offsetof(kernel_dirent, d_name) + 1;
			if (d_name_len > D_NAME_LEN_MAX)
				d_name_len = D_NAME_LEN_MAX;

			tprintf("%s{d_ino=%llu, d_off=%llu, d_reclen=%u"
				", d_name=", i ? ", " : "",
				zero_extend_signed_to_ull(d->d_ino),
				zero_extend_signed_to_ull(d->d_off),
				d->d_reclen);

			print_quoted_cstring(d->d_name, d_name_len);

			tprints(", d_type=");
			if (oob)
				tprints("?");
			else
				printxval(dirent_types, buf[i + d->d_reclen - 1], "DT_???");
			tprints("}");
		}
		dents++;
		if (d->d_reclen < sizeof(kernel_dirent)) {
			tprints_comment("d_reclen < sizeof(struct dirent)");
			break;
		}
		i += d->d_reclen;
	}
	if (!abbrev(tcp))
		tprints("]");
	else
		tprintf_comment("%u entries", dents);
	tprintf(", %u", count);
	free(buf);
	return 0;
}
