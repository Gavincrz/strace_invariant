#include "defs.h"
#include <sys/vfs.h>

SYS_FUNC(statfs)
{
	if (entering(tcp)) {
		printpath(tcp, tcp->u_arg[0]);
		tprints(", ");
	} else {
		print_struct_statfs(tcp, tcp->u_arg[1]);
	}
	return 0;
}

#define NUM_RET_STATFS 2
INV_FUNC(statfs)
{
	static int *ibuf = NULL;
	static int vcount;
	static int num_ret = NUM_RET_STATFS;

	if (tcp->flags & TCB_INV_TRACE){

	}
	else if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
		if (ibuf == NULL){
			vcount = read_fuzz_file(FUZZ_FILE(statfs), &ibuf, num_ret);
		}
		if (vcount >= 0 && count >= vcount){
			// read the original data
			unsigned int len = sizeof(struct statfs);
			struct statfs fetch_stat;
			tfetch_mem(tcp, tcp->u_arg[1], len, &fetch_stat);

			kernel_long_t ret = tcp->u_rval;

			m_set mlist[NUM_RET_STATFS] = {{&fetch_stat, len, VARIABLE_NORMAL},\
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