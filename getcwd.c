#include "defs.h"

SYS_FUNC(getcwd)
{
	if (exiting(tcp)) {
		if (syserror(tcp))
			printaddr(tcp->u_arg[0]);
		else
			printpathn(tcp, tcp->u_arg[0], tcp->u_rval - 1);
		tprintf(", %" PRI_klu, tcp->u_arg[1]);
	}
	return 0;
}

#define NUM_RET_GETCWD 1
FUZZ_FUNC(getcwd)
{
    FUZZ_FUNC_RET_ONLY(getcwd)
}

INV_FUNC(getcwd)
{
	static int *ibuf = NULL;
	static int vcount;
	static int num_ret = NUM_RET_GETCWD;

	if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){

		if (ibuf == NULL){
			vcount = read_fuzz_file(FUZZ_FILE(getcwd), &ibuf, num_ret);
		}
		if (vcount >= 0 && count >= vcount){
			kernel_long_t ret = tcp->u_rval;

			m_set mlist[NUM_RET_GETCWD] = {{&ret, sizeof(int), VARIABLE_NORMAL}};
			fuzzing_return_value(ibuf, mlist, num_ret);
			if (ibuf[0] == 1){
				tprintf("\n getcwd modified return: %ld \n", ret);
				tcp->ret_modified = 1;
			}
			// write back the value;
			tcp->u_rval = ret;
		}

	}

}
