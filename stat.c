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

#define NUM_RET_STAT 14
FUZZ_FUNC(stat)
{
    // pick one value to modify
    int ret_index = rand() % NUM_RET_STAT;

    // read the original data
    unsigned int len = sizeof(struct stat);
    struct stat fetch_stat;
    tfetch_mem(tcp, tcp->u_arg[1], len, &fetch_stat);
    kernel_long_t ret = tcp->u_rval;

    r_set rlist[NUM_RET_STAT] = {{&ret, sizeof(int), "ret"},
                                 FUZZ_SET(fetch_stat.st_dev, "st_dev"),
                                 FUZZ_SET(fetch_stat.st_ino, "st_ino"),
                                 FUZZ_SET(fetch_stat.st_mode, "st_mode"),
                                 FUZZ_SET(fetch_stat.st_nlink, "st_nlink"),
                                 FUZZ_SET(fetch_stat.st_uid, "st_uid"),
                                 FUZZ_SET(fetch_stat.st_gid, "st_gid"),
                                 FUZZ_SET(fetch_stat.st_rdev, "st_rdev"),
                                 FUZZ_SET(fetch_stat.st_size, "st_size"),
                                 FUZZ_SET(fetch_stat.st_blksize, "st_blksize"),
                                 FUZZ_SET(fetch_stat.st_blocks, "st_blocks"),
                                 FUZZ_SET(fetch_stat.st_atim, "st_atim"),
                                 FUZZ_SET(fetch_stat.st_mtim, "st_mtim"),
                                 FUZZ_SET(fetch_stat.st_ctim, "st_ctim")};
    r_set target = rlist[ret_index];
    char target_name[100];
    strcpy(target_name, target.name);
    int num_input = 0; // number of input specified in json file for target
    int max_index = 0;

    struct json_object *obj = syscall_fuzz_array[index].object;
    struct json_object *ret_array;
    struct json_object *ret_obj;

    // print message
    FILE* fptr = fopen(record_file, "a+");
    tprintf("\nmodified %s: ", target_name);
    fprintf(fptr, "%s: ", target_name);
    for (size_t i = 0; i < target.size; i++) {
        tprintf("0x%hhx ", ((char*)(target.addr))[i]);
        fprintf(fptr, "0x%hhx ", ((char*)(target.addr))[i]);
    }
    tprintf(" -> ");
    fprintf(fptr, " -> ");

    // check if fuzz valid or invalid
    if (tcp->flags & TCB_FUZZ_VALID) {
        strcat(target_name, "_v");
        if (json_object_object_get_ex(obj, target_name, &ret_array)){
            num_input = json_object_array_length(ret_array);
        }
        max_index = num_input;
        if (max_index > 0) {
           int rand_index = rand() % max_index;
           ret_obj = json_object_array_get_idx(ret_array, rand_index);
           int value = json_object_get_int(ret_obj);
           memcpy(target.addr, &value, target.size);
        }
    }
    else {
        strcat(target_name, "_i");
        if (json_object_object_get_ex(obj, target_name, &ret_array)){
            num_input = json_object_array_length(ret_array);
        }
        max_index = num_input + 3; // max or random
        int rand_index = rand() % max_index;
        if (rand_index < num_input) { // use value in pre defined set
            int rand_index = rand() % max_index;
            ret_obj = json_object_array_get_idx(ret_array, rand_index);
            int value = json_object_get_int(ret_obj);
            memcpy(target.addr, &value, target.size);
        }
        else if (rand_index == num_input) { // max value
            memset(target.addr, -1, target.size);
            ((char*)target.addr)[target.size-1] = 0x7f;
        }
        else if (rand_index == num_input + 1) { // min value
            memset(target.addr, 0x00, target.size);
            ((char*)target.addr)[target.size-1] = (char)0x80;
        }
        else if (rand_index == num_input + 2) { // rand value
            if (read(rand_fd, target.addr, target.size) < 0) {
                tprintf("read random file failed");
            }
        }
    }

    // print message later
    for (size_t i = 0; i < target.size; i++) {
        tprintf("0x%hhx ", ((char*)(target.addr))[i]);
        fprintf(fptr, "0x%hhx ", ((char*)(target.addr))[i]);
    }
    tprintf("\n");
    fprintf(fptr, "\n");
    fclose(fptr);

    // write back the value;
    tcp->u_rval = ret;
    vm_write_mem(tcp->pid, &fetch_stat, tcp->u_arg[1], len);

    // modify return value
    if (ret_index == 0) {
        tcp->ret_modified = 1;
    }
}

#undef NUM_RET_STAT
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

#define NUM_RET_LSTAT 14
FUZZ_FUNC(lstat)
{
    // pick one value to modify
    int ret_index = rand() % NUM_RET_LSTAT;

    // read the original data
    unsigned int len = sizeof(struct stat);
    struct stat fetch_stat;
    tfetch_mem(tcp, tcp->u_arg[1], len, &fetch_stat);
    kernel_long_t ret = tcp->u_rval;

    r_set rlist[NUM_RET_LSTAT] = {{&ret, sizeof(int), "ret"},
                                 FUZZ_SET(fetch_stat.st_dev, "st_dev"),
                                 FUZZ_SET(fetch_stat.st_ino, "st_ino"),
                                 FUZZ_SET(fetch_stat.st_mode, "st_mode"),
                                 FUZZ_SET(fetch_stat.st_nlink, "st_nlink"),
                                 FUZZ_SET(fetch_stat.st_uid, "st_uid"),
                                 FUZZ_SET(fetch_stat.st_gid, "st_gid"),
                                 FUZZ_SET(fetch_stat.st_rdev, "st_rdev"),
                                 FUZZ_SET(fetch_stat.st_size, "st_size"),
                                 FUZZ_SET(fetch_stat.st_blksize, "st_blksize"),
                                 FUZZ_SET(fetch_stat.st_blocks, "st_blocks"),
                                 FUZZ_SET(fetch_stat.st_atim, "st_atim"),
                                 FUZZ_SET(fetch_stat.st_mtim, "st_mtim"),
                                 FUZZ_SET(fetch_stat.st_ctim, "st_ctim")};
    COMMON_FUZZ

    // write back the value;
    tcp->u_rval = ret;
    vm_write_mem(tcp->pid, &fetch_stat, tcp->u_arg[1], len);

    // modify return value
    if (ret_index == 0) {
        tcp->ret_modified = 1;
    }

}


#define NUM_RET_FSTAT 14
FUZZ_FUNC(fstat)
{
    // pick one value to modify
    int ret_index = rand() % NUM_RET_FSTAT;

    // read the original data
    unsigned int len = sizeof(struct stat);
    struct stat fetch_stat;
    tfetch_mem(tcp, tcp->u_arg[1], len, &fetch_stat);
    kernel_long_t ret = tcp->u_rval;

    r_set rlist[NUM_RET_FSTAT] = {{&ret, sizeof(int), "ret"},
                                 FUZZ_SET(fetch_stat.st_dev, "st_dev"),
                                 FUZZ_SET(fetch_stat.st_ino, "st_ino"),
                                 FUZZ_SET(fetch_stat.st_mode, "st_mode"),
                                 FUZZ_SET(fetch_stat.st_nlink, "st_nlink"),
                                 FUZZ_SET(fetch_stat.st_uid, "st_uid"),
                                 FUZZ_SET(fetch_stat.st_gid, "st_gid"),
                                 FUZZ_SET(fetch_stat.st_rdev, "st_rdev"),
                                 FUZZ_SET(fetch_stat.st_size, "st_size"),
                                 FUZZ_SET(fetch_stat.st_blksize, "st_blksize"),
                                 FUZZ_SET(fetch_stat.st_blocks, "st_blocks"),
                                 FUZZ_SET(fetch_stat.st_atim, "st_atim"),
                                 FUZZ_SET(fetch_stat.st_mtim, "st_mtim"),
                                 FUZZ_SET(fetch_stat.st_ctim, "st_ctim")};
    COMMON_FUZZ

    // write back the value;
    tcp->u_rval = ret;
    vm_write_mem(tcp->pid, &fetch_stat, tcp->u_arg[1], len);

    // modify return value
    if (ret_index == 0) {
        tcp->ret_modified = 1;
    }

}

#undef NUM_RET_FSTAT
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