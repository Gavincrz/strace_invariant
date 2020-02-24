/*
 * Copyright (c) 2005-2015 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2015-2017 The strace developers.
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
#include "stat.h"
#include <sys/types.h>
#include <sys/stat.h>

static void
decode_struct_stat(struct tcb *const tcp, const kernel_ulong_t addr)
{
	struct strace_stat st;

	if (fetch_struct_stat(tcp, addr, &st))
		print_struct_stat(tcp, &st);
}

#define NUM_RET_STAT 2
INV_FUNC(stat)
{

    static int *ibuf = NULL;
    static int vcount;
    static int num_ret = NUM_RET_STAT;
    if (tcp->flags & TCB_INV_TRACE){
        //
    }
    else if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){

        if (ibuf == NULL){
            vcount = read_fuzz_file(FUZZ_FILE(stat), &ibuf, num_ret);
        }
        if (vcount >= 0 && count >= vcount){
            // read the original data
            unsigned int len = sizeof(struct stat);
            struct stat fetch_stat;
            tfetch_mem(tcp, tcp->u_arg[1], len, &fetch_stat);

            kernel_long_t ret = tcp->u_rval;
            m_set mlist[NUM_RET_STAT] = {{&fetch_stat, len, VARIABLE_NORMAL},\
                                        {&ret, sizeof(int), VARIABLE_NORMAL}};
            fuzzing_return_value(ibuf, mlist, num_ret);

            if (ret != tcp->u_rval){
                tprintf("\nmodified return: %ld \n", ret);
                tcp->ret_modified = 1;
            }
            // write back the value;
            tcp->u_rval = ret;
            vm_write_mem(tcp->pid, &fetch_stat, tcp->u_arg[1], len);
        }
    }
}

SYS_FUNC(stat)
{
	if (entering(tcp)) {
		printpath(tcp, tcp->u_arg[0]);
		tprints(", ");
	} else {
		decode_struct_stat(tcp, tcp->u_arg[1]);
	}
	return 0;
}


#define NUM_RET_FSTAT 2
INV_FUNC(fstat)
{
    static int *ibuf = NULL;
    static int vcount;
    static int num_ret = NUM_RET_FSTAT;

    if (tcp->flags & TCB_INV_TRACE){

    }
    else if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
        if (ibuf == NULL){
            vcount = read_fuzz_file(FUZZ_FILE(fstat), &ibuf, num_ret);
        }
        if (vcount >= 0 && count >= vcount){
            // read the original data
            unsigned int len = sizeof(struct stat);
            struct stat fetch_stat;
            tfetch_mem(tcp, tcp->u_arg[1], len, &fetch_stat);

            kernel_long_t ret = tcp->u_rval;

            m_set mlist[NUM_RET_FSTAT] = {{&fetch_stat, len, VARIABLE_NORMAL},\
                                        {&ret, sizeof(int), VARIABLE_NORMAL}};
            fuzzing_return_value(ibuf, mlist, num_ret);
			if (ibuf[1] == 1){
				tprintf("\nmodified return: %ld \n", ret);
				tcp->ret_modified = 1;
			}
            // write back the value;
            tcp->u_rval = ret;
            vm_write_mem(tcp->pid, &fetch_stat, tcp->u_arg[1], len);
        }

    }
}

SYS_FUNC(fstat)
{
	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
		using_ori_fd(tcp);
	} else {
		decode_struct_stat(tcp, tcp->u_arg[1]);
	}
	return 0;
}

SYS_FUNC(newfstatat)
{
	if (entering(tcp)) {
		print_dirfd(tcp, tcp->u_arg[0]);
		printpath(tcp, tcp->u_arg[1]);
		tprints(", ");
	} else {
		decode_struct_stat(tcp, tcp->u_arg[2]);
		tprints(", ");
		printflags(at_flags, tcp->u_arg[3], "AT_???");
	}
	return 0;
}


#define NUM_RET_NEW_FSTAT 2
INV_FUNC(newfstatat)
{
    static int *ibuf = NULL;
    static int vcount;
    static int num_ret = NUM_RET_NEW_FSTAT;

    if (tcp->flags & TCB_INV_TRACE){

    }
    else if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
        if (ibuf == NULL){
            vcount = read_fuzz_file(FUZZ_FILE(newfstatat), &ibuf, num_ret);
        }
        if (vcount >= 0 && count >= vcount){
            // read the original data
            unsigned int len = sizeof(struct stat);
            struct stat fetch_stat;
            tfetch_mem(tcp, tcp->u_arg[2], len, &fetch_stat);

            kernel_long_t ret = tcp->u_rval;

            m_set mlist[NUM_RET_NEW_FSTAT] = {{&fetch_stat, len, VARIABLE_NORMAL},\
                                        {&ret, sizeof(int), VARIABLE_NORMAL}};
            fuzzing_return_value(ibuf, mlist, num_ret);
            if (ibuf[1] == 1){
                tprintf("\nmodified return: %ld \n", ret);
                tcp->ret_modified = 1;
            }
            // write back the value;
            tcp->u_rval = ret;
            vm_write_mem(tcp->pid, &fetch_stat, tcp->u_arg[2], len);
        }

    }
}