#define arch_set_error arm_set_error
#define arch_set_success arm_set_success
#define arch_set_all arm_set_all
#include <defs.h>
#include "arm/set_error.c"
#undef arch_set_success
#undef arch_set_error
#undef arch_set_all

static int
arch_set_error(struct tcb *tcp)
{
	if (aarch64_io.iov_len == sizeof(arm_regs))
		return arm_set_error(tcp);

	aarch64_regs.regs[0] = -tcp->u_error;
	return set_regs(tcp->pid);
}

static int
arch_set_success(struct tcb *tcp)
{
	if (aarch64_io.iov_len == sizeof(arm_regs))
		return arm_set_success(tcp);

	aarch64_regs.regs[0] = tcp->u_rval;
	return set_regs(tcp->pid);
}

static int
arch_set_all(struct tcb *tcp)
{
    for(int i = 0; i < MAX_ARGS; i++){
        if (tcp->u_arg[i] != tcp->m_arg[i]){
            aarch64_regs.regs[i] = tcp->m_arg[i];
        }
    }
    if (tcp->u_rval != tcp->m_rval){
        aarch64_regs.regs[0] = tcp->m_arg;
    }
	return set_regs(tcp->pid);
}