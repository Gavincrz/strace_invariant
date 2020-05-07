/*
 * Copyright (c) 2013 Luca Clementi <luca.clementi@gmail.com>
 * Copyright (c) 2013-2018 The strace developers.
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
#include "unwind.h"

#include "mmap_cache.h"
#include <libunwind-ptrace.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#define MAX_REGIONS 1024
static unw_addr_space_t libunwind_as;

struct mem_region
{
    unsigned long start_addr;
    unsigned long end_addr;
    void* data;
};


struct proc_info
{
    char reserved[256]; // reserved for UPT_info
    char map_path[64]; // even they already saved in UPT_info, have no access to it
    char mem_path[64];
    int num_regions;
    struct mem_region regions[MAX_REGIONS]; // create a max region, assume not excess

};


void
free_mem_region(struct proc_info* info)
{
    for (int i = 0; i < MAX_REGIONS; i++)
    {
        free(info->regions[i].data);
        info->regions[i].data = NULL;
    }
}

void
init_proc_info(struct proc_info* info, int pid)
{
    // initialize them with invalid
    sprintf(info->map_path, "/proc/%d/maps", pid);
    sprintf(info->mem_path, "/proc/%d/mem", pid);
    perror_msg("map path is: %s\n", info->map_path);
    perror_msg("mem path is: %s\n", info->mem_path);
    info->num_regions = 0;
    perror_msg("size of regions = %ld", sizeof(info->regions));
    memset(&(info->regions), 0, sizeof(info->regions));
}

int
find_mem_region(struct proc_info* info, unw_word_t addr)
{
    for (int i = 0; i < info->num_regions; i++)
    {
        if (addr >= info->regions[i].start_addr
        && addr < info->regions[i].end_addr){
            // address found
            return i;
        }
    }
    return -1;
}

void
get_mem_region_addr(struct proc_info* info)
{
    /* clear stored mem region */
    free_mem_region(info);
    FILE* map_fp = fopen(info->map_path, "r");
    if (!map_fp) {
        perror("Open maps");
        return;
    }

    // parsing maps file, find stack address range
    ssize_t line_size;
    char *line_buf = NULL;
    size_t line_buf_size = 0;
    line_size = getline(&line_buf, &line_buf_size, map_fp);
    char *ret;

    /* get number of regions first time */
    int region_count = 0;
    /* Loop through until we are done with the file. */
    while (line_size >= 0)
    {
        ret = strstr(line_buf, " r"); // only search for readable region
        if (ret) {
            if (region_count >= MAX_REGIONS) {
                error_msg_and_die("region count reached MAX_REGION");
            }
            /* parsing and get the address */
            char * addr_str = strtok(line_buf, " ");
            sscanf(addr_str, "%lx-%lx", &(info->regions[region_count].start_addr),
                   &(info->regions[region_count].end_addr));

            region_count++;
        }
        /* Get the next line */
        line_size = getline(&line_buf, &line_buf_size, map_fp);
    }
    info->num_regions = region_count;
    free(line_buf);
    line_buf = NULL;
    fclose(map_fp);


//    for (int i = 0; i < info->num_regions; i++) {
//        perror_msg("0x%lx - 0x%lx", info->regions[i].start_addr, info->regions[i].end_addr);
//    }
}

int
_proc_access_mem (unw_addr_space_t as, unw_word_t addr, unw_word_t *val,
                 int write, void *arg) {
    if (write) {
        perror_msg("customized accessor do not support mem write, use original ptrace\n");
        return _UPT_accessors.access_mem(as, addr, val, write, arg);
    }


    struct proc_info *info = (struct proc_info *)arg;
    // lazy load mem regions
    int index = find_mem_region(info, addr);
    if (index < 0) {
//        perror_msg("can not find addr 0x%lx, use default ptrace, ptrace return = %d", addr, ret);
        return -UNW_EINVAL;
    }
    struct mem_region* region = &(info->regions[index]);
    // load the mem region if needed
    if (!region->data)
    {
        int mem_fd = open(info->mem_path, O_RDONLY);
        if (mem_fd < 0) {
            perror_msg_and_die("Open mem file");
            return _UPT_accessors.access_mem(as, addr, val, write, arg);
        }
        unsigned long region_size = region->end_addr - region->start_addr;
        region->data = malloc(sizeof(char) * region_size);

        /* start read from stack location */
        if (lseek(mem_fd, region->start_addr, SEEK_SET) < 0) {
            perror_msg_and_die("Lseek mem");
            close(mem_fd);
            free(region->data);
            region->data = NULL;
            return _UPT_accessors.access_mem(as, addr, val, write, arg);
        }

        if (read(mem_fd, region->data, region_size) < 0) {
            perror_msg_and_die("Read mem");
            close(mem_fd);
            free(region->data);
            region->data = NULL;
            return _UPT_accessors.access_mem(as, addr, val, write, arg);
        }
        close(mem_fd);
    }

    // access the memory
    *val = *(unw_word_t *)(region->data + (addr - region->start_addr));
    return 0;
}


static void
init(void)
{
	mmap_cache_enable();
	if (proc_unwind) {
        unw_accessors_t proc_accessors = _UPT_accessors;
        proc_accessors.access_mem = _proc_access_mem;
        libunwind_as = unw_create_addr_space(&proc_accessors, 0);
	}
    else{
        libunwind_as = unw_create_addr_space(&_UPT_accessors, 0);
    }
	if (!libunwind_as)
		error_msg_and_die("failed to create address space"
				  " for stack tracing");
	unw_set_caching_policy(libunwind_as, UNW_CACHE_GLOBAL);
}

static void *
tcb_init(struct tcb *tcp)
{
	void *r = _UPT_create(tcp->pid);

	if (!r)
		perror_msg_and_die("_UPT_create");

	if (proc_unwind){
        /* reallocate */
        r = realloc(r, sizeof(struct proc_info));
        /* initialize the part used for proc mem */
        struct proc_info* info = (struct proc_info*)r;
        init_proc_info(info, tcp->pid);
	}
	return r;
}

static void
tcb_fin(struct tcb *tcp)
{
    if (proc_unwind) {
        free_mem_region((struct proc_info *) tcp->unwind_ctx);
    }
	_UPT_destroy(tcp->unwind_ctx);
}

static void
get_symbol_name(unw_cursor_t *cursor, char **name,
		size_t *size, unw_word_t *offset)
{
	for (;;) {
		int rc = unw_get_proc_name(cursor, *name, *size, offset);

		if (rc == 0)
			break;
		if (rc != -UNW_ENOMEM) {
			**name = '\0';
			*offset = 0;
			break;
		}
		*name = xgrowarray(*name, size, 1);
	}
}

static int
print_stack_frame(struct tcb *tcp,
		  unwind_call_action_fn call_action,
		  unwind_error_action_fn error_action,
		  void *data,
		  unw_cursor_t *cursor,
		  char **symbol_name,
		  size_t *symbol_name_size)
{
	unw_word_t ip;

	if (unw_get_reg(cursor, UNW_REG_IP, &ip) < 0) {
		perror_msg("cannot walk the stack of process %d", tcp->pid);
		return -1;
	}

	struct mmap_cache_entry_t *entry = mmap_cache_search(tcp, ip);

	if (entry
	    /* ignore mappings that have no PROT_EXEC bit set */
	    && (entry->protections & MMAP_CACHE_PROT_EXECUTABLE)) {
		unw_word_t function_offset;

		get_symbol_name(cursor, symbol_name, symbol_name_size,
				&function_offset);
		unsigned long true_offset =
			ip - entry->start_addr + entry->mmap_offset;
		call_action(data,
			    entry->binary_filename,
			    *symbol_name,
			    function_offset,
			    true_offset);

		return 0;
	}

	/*
	 * there is a bug in libunwind >= 1.0
	 * after a set_tid_address syscall
	 * unw_get_reg returns IP == 0
	 */
	if (ip)
		error_action(data, "unexpected_backtracing_error", ip);
	return -1;
}

static void
walk(struct tcb *tcp,
     unwind_call_action_fn call_action,
     unwind_error_action_fn error_action,
     void *data)
{
	char *symbol_name;
	size_t symbol_name_size = 40;
	unw_cursor_t cursor;
	int stack_depth;

	if (!tcp->mmap_cache)
		error_func_msg_and_die("mmap_cache is NULL");

	symbol_name = xmalloc(symbol_name_size);

	if (unw_init_remote(&cursor, libunwind_as, tcp->unwind_ctx) < 0)
		perror_func_msg_and_die("cannot initialize libunwind");

	if (proc_unwind) {
        /* also reload the mem map */
        struct proc_info* info = (struct proc_info*) tcp->unwind_ctx;
        get_mem_region_addr(info);
	}

	for (stack_depth = 0; stack_depth < 256; ++stack_depth) {
		if (print_stack_frame(tcp, call_action, error_action, data,
				&cursor, &symbol_name, &symbol_name_size) < 0)
			break;
		if (unw_step(&cursor) <= 0)
			break;
	}
	if (stack_depth >= 256)
		error_action(data, "too many stack frames", 0);

	free(symbol_name);
}

static void
tcb_walk(struct tcb *tcp,
	 unwind_call_action_fn call_action,
	 unwind_error_action_fn error_action,
	 void *data)
{
	switch (mmap_cache_rebuild_if_invalid(tcp, __func__)) {
		case MMAP_CACHE_REBUILD_RENEWED:
			/*
			 * Rebuild the unwinder internal cache.
			 * Called when mmap cache subsystem detects a
			 * change of tracee memory mapping.
			 */
			unw_flush_cache(libunwind_as, 0, 0);
			ATTRIBUTE_FALLTHROUGH;
		case MMAP_CACHE_REBUILD_READY:
			walk(tcp, call_action, error_action, data);
			break;
		default:
			/* Do nothing */
			;
	}
}

const struct unwind_unwinder_t unwinder = {
	.name = "libunwind",
	.init = init,
	.tcb_init = tcb_init,
	.tcb_fin = tcb_fin,
	.tcb_walk = tcb_walk,
};
