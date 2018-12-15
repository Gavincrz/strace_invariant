#include <kernel_types.h>

static int
arch_set_error(struct tcb *tcp)
{
	kernel_ulong_t	rval = -(long) tcp->u_error;

	if (tcp->currpers == 1)
		i386_regs.eax = rval;
	else
		x86_64_regs.rax = rval;

	return upoke(tcp, 8 * RAX, rval);
}

static int
arch_set_success(struct tcb *tcp)
{
	kernel_ulong_t  rval = (kernel_ulong_t) tcp->u_rval;

	if (tcp->currpers == 1)
		i386_regs.eax = rval;
	else
		x86_64_regs.rax = rval;

	return upoke(tcp, 8 * RAX, rval);
}

static int
arch_set_all_reg(struct tcb *tcp)
{

    x86_64_regs.rdi = tcp->u_arg[0];
    x86_64_regs.rsi = tcp->u_arg[1];
    x86_64_regs.rdx = tcp->u_arg[2];
    x86_64_regs.r10 = tcp->u_arg[3];
    x86_64_regs.r8 = tcp->u_arg[4];
    x86_64_regs.r9 = tcp->u_arg[5];
	return  ptrace(PTRACE_SETREGS, tcp->pid, NULL, &x86_64_regs);
}
