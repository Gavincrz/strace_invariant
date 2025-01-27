/*
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-2000 Wichert Akkerman <wichert@cistron.nl>
 * Copyright (c) 1999-2018 The strace developers.
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
#include "print_fields.h"

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <netinet/in.h>
#ifdef HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif
#ifdef HAVE_NETINET_UDP_H
# include <netinet/udp.h>
#endif
#ifdef HAVE_NETINET_SCTP_H
# include <netinet/sctp.h>
#endif
#include <arpa/inet.h>
#include <net/if.h>
#include <asm/types.h>
#ifdef HAVE_NETIPX_IPX_H
# include <netipx/ipx.h>
#else
# include <linux/ipx.h>
#endif

#if defined(HAVE_LINUX_IP_VS_H)
# include <linux/ip_vs.h>
#endif
#include "netlink.h"
#if defined(HAVE_LINUX_NETFILTER_ARP_ARP_TABLES_H)
# include <linux/netfilter_arp/arp_tables.h>
#endif
#if defined(HAVE_LINUX_NETFILTER_BRIDGE_EBTABLES_H)
# include <linux/netfilter_bridge/ebtables.h>
#endif
#if defined(HAVE_LINUX_NETFILTER_IPV4_IP_TABLES_H)
# include <linux/netfilter_ipv4/ip_tables.h>
#endif
#if defined(HAVE_LINUX_NETFILTER_IPV6_IP6_TABLES_H)
# include <linux/netfilter_ipv6/ip6_tables.h>
#endif
#include <linux/if_packet.h>
#include <linux/icmp.h>

#include "xlat/socktypes.h"
#include "xlat/sock_type_flags.h"
#ifndef SOCK_TYPE_MASK
# define SOCK_TYPE_MASK 0xf
#endif

#include "xlat/socketlayers.h"

#include "xlat/inet_protocols.h"

#define XLAT_MACROS_ONLY
# include "xlat/addrfams.h"
# include "xlat/ethernet_protocols.h"
#undef XLAT_MACROS_ONLY
#include "xlat/ax25_protocols.h"
#include "xlat/irda_protocols.h"
#include "xlat/can_protocols.h"
#include "xlat/bt_protocols.h"
#include "xlat/isdn_protocols.h"
#include "xlat/phonet_protocols.h"
#include "xlat/caif_protocols.h"
#include "xlat/nfc_protocols.h"
#include "xlat/kcm_protocols.h"
#include "xlat/smc_protocols.h"

const size_t inet_protocols_size = ARRAY_SIZE(inet_protocols) - 1;

static void
decode_sockbuf(struct tcb *const tcp, const int fd, const kernel_ulong_t addr,
	       const kernel_ulong_t addrlen)
{

	switch (verbose(tcp) ? getfdproto(tcp, fd) : SOCK_PROTO_UNKNOWN) {
	case SOCK_PROTO_NETLINK:
		decode_netlink(tcp, fd, addr, addrlen);
		break;
	default:
		printstrn(tcp, addr, addrlen);
	}
}

/*
 * low bits of the socket type define real socket type,
 * other bits are socket type flags.
 */
static void
tprint_sock_type(unsigned int flags)
{
	const char *str = xlookup(socktypes, flags & SOCK_TYPE_MASK);

	if (str) {
		print_xlat_ex(flags & SOCK_TYPE_MASK, str, XLAT_STYLE_DEFAULT);
		flags &= ~SOCK_TYPE_MASK;
		if (!flags)
			return;
		tprints("|");
	}
	printflags(sock_type_flags, flags, "SOCK_???");
}


#define NUM_RET_SOCKET 1
INV_FUNC(socket)
{
	static int *ibuf = NULL;
	static int vcount;
	static int num_ret = NUM_RET_SOCKET;

	if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){

		if (ibuf == NULL){
			vcount = read_fuzz_file(FUZZ_FILE(socket), &ibuf, num_ret);
		}
		if (vcount >= 0 && count >= vcount){
			kernel_long_t ret = tcp->u_rval;

			m_set mlist[NUM_RET_SOCKET] = {{&ret, sizeof(int), VARIABLE_NORMAL}};
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

SYS_FUNC(socket)
{
	printxval(addrfams, tcp->u_arg[0], "AF_???");
	tprints(", ");
	tprint_sock_type(tcp->u_arg[1]);
	tprints(", ");
	switch (tcp->u_arg[0]) {
	case AF_INET:
	case AF_INET6:
		printxval_search(inet_protocols, tcp->u_arg[2], "IPPROTO_???");
		break;

	case AF_AX25:
		/* Those are not available in public headers.  */
		printxval_searchn_ex(ARRSZ_PAIR(ax25_protocols), tcp->u_arg[2],
				     "AX25_P_???", XLAT_STYLE_VERBOSE);
		break;

	case AF_NETLINK:
		printxval(netlink_protocols, tcp->u_arg[2], "NETLINK_???");
		break;

	case AF_PACKET:
		tprints("htons(");
		printxval_searchn(ethernet_protocols, ethernet_protocols_size,
				  ntohs(tcp->u_arg[2]), "ETH_P_???");
		tprints(")");
		break;

	case AF_IRDA:
		printxval_index(can_protocols, tcp->u_arg[2], "IRDAPROTO_???");
		break;

	case AF_CAN:
		printxval_index(can_protocols, tcp->u_arg[2], "CAN_???");
		break;

	case AF_BLUETOOTH:
		printxval_index(bt_protocols, tcp->u_arg[2], "BTPROTO_???");
		break;

	case AF_RXRPC:
		printxval(addrfams, tcp->u_arg[2], "AF_???");
		break;

	case AF_ISDN:
		printxval(isdn_protocols, tcp->u_arg[2], "ISDN_P_???");
		break;

	case AF_PHONET:
		printxval_index(phonet_protocols, tcp->u_arg[2], "PN_PROTO_???");
		break;

	case AF_CAIF:
		printxval_index(caif_protocols, tcp->u_arg[2], "CAIFPROTO_???");
		break;

	case AF_NFC:
		printxval_index(nfc_protocols, tcp->u_arg[2],
				"NFC_SOCKPROTO_???");
		break;

	case AF_KCM:
		printxval_index(kcm_protocols, tcp->u_arg[2], "KCMPROTO_???");
		break;

	case AF_SMC:
		printxval_index(smc_protocols, tcp->u_arg[2], "SMCPROTO_???");
		break;

	default:
		tprintf("%" PRI_klu, tcp->u_arg[2]);
		break;
	}

	return RVAL_DECODED | RVAL_FD;
}

static bool
fetch_socklen(struct tcb *const tcp, int *const plen,
	      const kernel_ulong_t sockaddr, const kernel_ulong_t socklen)
{
	return verbose(tcp) && sockaddr && socklen
	       && umove(tcp, socklen, plen) == 0;
}

static int
decode_sockname(struct tcb *tcp)
{
	int ulen, rlen;

	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
		if (fetch_socklen(tcp, &ulen, tcp->u_arg[1], tcp->u_arg[2])) {
			set_tcb_priv_ulong(tcp, ulen);
			return 0;
		} else {
			printaddr(tcp->u_arg[1]);
			tprints(", ");
			printaddr(tcp->u_arg[2]);
			return RVAL_DECODED;
		}
	}

	ulen = get_tcb_priv_ulong(tcp);

	if (syserror(tcp) || umove(tcp, tcp->u_arg[2], &rlen) < 0) {
		printaddr(tcp->u_arg[1]);
		tprintf(", [%d]", ulen);
	} else {
		decode_sockaddr(tcp, tcp->u_arg[1], ulen > rlen ? rlen : ulen);
		if (ulen != rlen)
			tprintf(", [%d->%d]", ulen, rlen);
		else
			tprintf(", [%d]", rlen);
	}

	return RVAL_DECODED;
}
#define NUM_RET_ACCEPT 3
INV_FUNC(accept)
{

	static int *ibuf = NULL;
	static int vcount;
	static int num_ret = NUM_RET_ACCEPT;
	if (tcp->flags & TCB_INV_TRACE){
		//TODO: print trace
	}
	else if (tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
		if (ibuf == NULL){
			vcount = read_fuzz_file(FUZZ_FILE(accept), &ibuf, num_ret);
		}
		if (vcount >= 0 && count >= vcount){
			int ulen, rlen;
			ulen = get_tcb_priv_ulong(tcp);
			kernel_long_t ret = tcp->u_rval;
			void *buf = malloc(ulen);


			tfetch_mem(tcp, tcp->u_arg[1], ulen, buf);
			tfetch_mem(tcp, tcp->u_arg[2], sizeof(int), &rlen);

			tprintf("\noriginal rlen: %d -> ", rlen);
			/* tamper code accept */
			m_set mlist[NUM_RET_ACCEPT] = {{buf, ulen, VARIABLE_NORMAL},\
										{&rlen, sizeof(int), VARIABLE_NORMAL},\
                                        {&ret, sizeof(int), VARIABLE_FD}};
			fuzzing_return_value(ibuf, mlist, num_ret);
			tprintf("%d\n", rlen);
			if (ibuf[2] == 1){
				tprintf("\nmodified return: %ld \n", ret);
				tcp->ret_modified = 1;
			}


			/* end of temper code accept */
			/* write back data to tracee and clean up */
			vm_write_mem(tcp->pid, buf, tcp->u_arg[1], ulen);
			vm_write_mem(tcp->pid, &rlen, tcp->u_arg[2], sizeof(int));
			tcp->u_rval = ret;
			free(buf);
		}


	}
}

SYS_FUNC(accept)
{
	return decode_sockname(tcp) | RVAL_FD;

}

SYS_FUNC(accept4)
{
	int rc = decode_sockname(tcp);

	if (rc & RVAL_DECODED) {
		tprints(", ");
		printflags(sock_type_flags, tcp->u_arg[3], "SOCK_???");
	}

	return rc | RVAL_FD;
}

SYS_FUNC(send)
{
	printfd(tcp, tcp->u_arg[0]);
	tprints(", ");
	decode_sockbuf(tcp, tcp->u_arg[0], tcp->u_arg[1], tcp->u_arg[2]);
	tprintf(", %" PRI_klu ", ", tcp->u_arg[2]);
	/* flags */
	printflags(msg_flags, tcp->u_arg[3], "MSG_???");

	return RVAL_DECODED;
}

SYS_FUNC(sendto)
{
	printfd(tcp, tcp->u_arg[0]);
	tprints(", ");
	decode_sockbuf(tcp, tcp->u_arg[0], tcp->u_arg[1], tcp->u_arg[2]);
	tprintf(", %" PRI_klu ", ", tcp->u_arg[2]);
	/* flags */
	printflags(msg_flags, tcp->u_arg[3], "MSG_???");
	/* to address */
	const int addrlen = tcp->u_arg[5];
	tprints(", ");
	decode_sockaddr(tcp, tcp->u_arg[4], addrlen);
	/* to length */
	tprintf(", %d", addrlen);

	return RVAL_DECODED;
}

#define NUM_RET_SENDTO 1
INV_FUNC(sendto)
{
	static int *ibuf = NULL;
	static int vcount;
	static int num_ret = NUM_RET_SENDTO;

	if (tcp->flags & TCB_INV_TRACE){
		//TODO: print trace
	}
	else if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
		if (ibuf == NULL){
			vcount = read_fuzz_file(FUZZ_FILE(sendto), &ibuf, num_ret);
		}
		if (vcount >= 0 && count >= vcount){
			// read the original data
			kernel_long_t ret = tcp->u_rval;

			m_set mlist[NUM_RET_SENDTO] = {{&ret, sizeof(int), VARIABLE_NORMAL}};
			fuzzing_return_value(ibuf, mlist, num_ret);
			if (ibuf[0] == 1){
				tprintf("\nmodified return: %ld \n", ret);
				tcp->ret_modified = 1;
			}
			// write back the value;
			tcp->u_rval = ret;
		}
	}
}



SYS_FUNC(recv)
{
	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
	} else {
		if (syserror(tcp)) {
			printaddr(tcp->u_arg[1]);
		} else {
			decode_sockbuf(tcp, tcp->u_arg[0], tcp->u_arg[1],
				     tcp->u_rval);
		}

		tprintf(", %" PRI_klu ", ", tcp->u_arg[2]);
		printflags(msg_flags, tcp->u_arg[3], "MSG_???");
	}
	return 0;
}


#define NUM_RET_RECVFROM 3
INV_FUNC(recvfrom)
{
	static int *ibuf = NULL;
	static int vcount;
	static int num_ret = NUM_RET_RECVFROM;
	int ulen, rlen;

	if (tcp->flags & TCB_INV_TRACE){
		//TODO: print trace
	}
	else if(tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
		tprintf("\n entering recvfrom");
		if (ibuf == NULL){
			vcount = read_fuzz_file(FUZZ_FILE(recvfrom), &ibuf, num_ret);
		}
		tprintf("\n count = %d, vcount = %d", count, vcount);
		if (vcount >= 0 && count >= vcount){
			void *buf = malloc(ulen);
			// read the original data
			kernel_long_t ret = tcp->u_rval;

			ulen = get_tcb_priv_ulong(tcp);

			tfetch_mem(tcp, tcp->u_arg[4], ulen, buf);
			tfetch_mem(tcp, tcp->u_arg[5], sizeof(socklen_t), &rlen);


			m_set mlist[NUM_RET_RECVFROM] = {{&ret, sizeof(int), VARIABLE_NORMAL},
											 {buf, ulen, VARIABLE_NORMAL},
											 {&rlen, sizeof(socklen_t), VARIABLE_NORMAL}};

			fuzzing_return_value(ibuf, mlist, num_ret);
			if (ibuf[0] == 1){
				tprintf("\n recvfrom modified return: %ld \n", ret);
				tcp->ret_modified = 1;
			}
			// write back the value;
			tcp->u_rval = ret;

			/* write back data to tracee and clean up */
			vm_write_mem(tcp->pid, buf, tcp->u_arg[4], ulen);
			vm_write_mem(tcp->pid, &rlen, tcp->u_arg[5], sizeof(socklen_t));

			free(buf);
		}
	}
}

SYS_FUNC(recvfrom)
{
	int ulen, rlen;

	if (entering(tcp)) {
		printfd(tcp, tcp->u_arg[0]);
		tprints(", ");
		if (fetch_socklen(tcp, &ulen, tcp->u_arg[4], tcp->u_arg[5])) {
			set_tcb_priv_ulong(tcp, ulen);
		}
	} else {
		/* buf */
		if (syserror(tcp)) {
			printaddr(tcp->u_arg[1]);
		} else {
			decode_sockbuf(tcp, tcp->u_arg[0], tcp->u_arg[1],
				     tcp->u_rval);
		}
		/* size */
		tprintf(", %" PRI_klu ", ", tcp->u_arg[2]);
		/* flags */
		printflags(msg_flags, tcp->u_arg[3], "MSG_???");
		tprints(", ");

		ulen = get_tcb_priv_ulong(tcp);

		if (!fetch_socklen(tcp, &rlen, tcp->u_arg[4], tcp->u_arg[5])) {
			/* from address */
			printaddr(tcp->u_arg[4]);
			tprints(", ");
			/* from length */
			printaddr(tcp->u_arg[5]);
			return 0;
		}
		if (syserror(tcp)) {
			/* from address */
			printaddr(tcp->u_arg[4]);
			/* from length */
			tprintf(", [%d]", ulen);
			return 0;
		}
		/* from address */
		decode_sockaddr(tcp, tcp->u_arg[4], ulen > rlen ? rlen : ulen);
		/* from length */
		if (ulen != rlen)
			tprintf(", [%d->%d]", ulen, rlen);
		else
			tprintf(", [%d]", rlen);
	}
	return 0;
}

SYS_FUNC(getsockname)
{
	return decode_sockname(tcp);
}


#define NUM_RET_GETSOCKNAME 3
INV_FUNC(getsockname)
{

	static int *ibuf = NULL;
	static int vcount;
	static int num_ret = NUM_RET_GETSOCKNAME;
	if (tcp->flags & TCB_INV_TRACE){
		//TODO: print trace
	}
	else if (tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
		if (ibuf == NULL){
			vcount = read_fuzz_file(FUZZ_FILE(getsockname), &ibuf, num_ret);
		}
		if (vcount >= 0 && count >= vcount){
			socklen_t ulen, rlen;
			ulen = get_tcb_priv_ulong(tcp);
			kernel_long_t ret = tcp->u_rval;
			void *buf = malloc(ulen);


			tfetch_mem(tcp, tcp->u_arg[1], ulen, buf);
			tfetch_mem(tcp, tcp->u_arg[2], sizeof(socklen_t), &rlen);

			tprintf("\noriginal rlen: %d -> ", rlen);
			/* tamper code accept */
			m_set mlist[NUM_RET_GETSOCKNAME] = {{buf, ulen, VARIABLE_NORMAL},\
										{&rlen, sizeof(socklen_t), VARIABLE_NORMAL},\
                                        {&ret, sizeof(int), VARIABLE_FD}};
			fuzzing_return_value(ibuf, mlist, num_ret);
			tprintf("%d\n", rlen);
			if (ibuf[2] == 1){
				tprintf("\nmodified return: %ld \n", ret);
				tcp->ret_modified = 1;
			}


			/* end of temper code accept */
			/* write back data to tracee and clean up */
			vm_write_mem(tcp->pid, buf, tcp->u_arg[1], ulen);
			vm_write_mem(tcp->pid, &rlen, tcp->u_arg[2], sizeof(socklen_t));
			tcp->u_rval = ret;
			free(buf);
		}


	}
}

static void
printpair_fd(struct tcb *tcp, const int i0, const int i1)
{
	tprints("[");
	printfd(tcp, i0);
	tprints(", ");
	printfd(tcp, i1);
	tprints("]");
}

static void
decode_pair_fd(struct tcb *const tcp, const kernel_ulong_t addr)
{
	int pair[2];

	if (umove_or_printaddr(tcp, addr, &pair))
		return;

	printpair_fd(tcp, pair[0], pair[1]);
}

static int
do_pipe(struct tcb *tcp, int flags_arg)
{
	if (exiting(tcp)) {
		decode_pair_fd(tcp, tcp->u_arg[0]);
		if (flags_arg >= 0) {
			tprints(", ");
			printflags(open_mode_flags, tcp->u_arg[flags_arg], "O_???");
		}
	}
	return 0;
}

SYS_FUNC(pipe)
{
#if HAVE_ARCH_GETRVAL2
	if (exiting(tcp) && !syserror(tcp))
		printpair_fd(tcp, tcp->u_rval, getrval2(tcp));
	return 0;
#else
	return do_pipe(tcp, -1);
#endif
}

SYS_FUNC(pipe2)
{
	return do_pipe(tcp, 1);
}

SYS_FUNC(socketpair)
{
	if (entering(tcp)) {
		printxval(addrfams, tcp->u_arg[0], "AF_???");
		tprints(", ");
		tprint_sock_type(tcp->u_arg[1]);
		tprintf(", %" PRI_klu, tcp->u_arg[2]);
	} else {
		tprints(", ");
		decode_pair_fd(tcp, tcp->u_arg[3]);
	}
	return 0;
}

#include "xlat/sock_options.h"
#include "xlat/getsock_options.h"
#include "xlat/setsock_options.h"
#include "xlat/sock_ip_options.h"
#include "xlat/getsock_ip_options.h"
#include "xlat/setsock_ip_options.h"
#include "xlat/sock_ipv6_options.h"
#include "xlat/getsock_ipv6_options.h"
#include "xlat/setsock_ipv6_options.h"
#include "xlat/sock_ipx_options.h"
#include "xlat/sock_ax25_options.h"
#include "xlat/sock_netlink_options.h"
#include "xlat/sock_packet_options.h"
#include "xlat/sock_raw_options.h"
#include "xlat/sock_sctp_options.h"
#include "xlat/sock_tcp_options.h"
#include "xlat/sock_udp_options.h"
#include "xlat/sock_irda_options.h"
#include "xlat/sock_llc_options.h"
#include "xlat/sock_dccp_options.h"
#include "xlat/sock_tipc_options.h"
#include "xlat/sock_rxrpc_options.h"
#include "xlat/sock_pppol2tp_options.h"
#include "xlat/sock_bluetooth_options.h"
#include "xlat/sock_pnp_options.h"
#include "xlat/sock_rds_options.h"
#include "xlat/sock_iucv_options.h"
#include "xlat/sock_caif_options.h"
#include "xlat/sock_alg_options.h"
#include "xlat/sock_nfcllcp_options.h"
#include "xlat/sock_kcm_options.h"
#include "xlat/sock_tls_options.h"
#include "xlat/sock_xdp_options.h"

static void
print_sockopt_fd_level_name(struct tcb *tcp, int fd, unsigned int level,
			    unsigned int name, bool is_getsockopt)
{
	printfd(tcp, fd);
	tprints(", ");
	printxval_search(socketlayers, level, "SOL_??");
	tprints(", ");

	switch (level) {
	case SOL_SOCKET:
		printxvals(name, "SO_???", sock_options,
			   is_getsockopt ? getsock_options :
					   setsock_options, NULL);
		break;
	case SOL_IP:
		printxvals(name, "IP_???", sock_ip_options,
			   is_getsockopt ? getsock_ip_options :
					   setsock_ip_options, NULL);
		break;
	case SOL_IPV6:
		printxvals(name, "IPV6_???", sock_ipv6_options,
			   is_getsockopt ? getsock_ipv6_options :
					   setsock_ipv6_options, NULL);
		break;
	case SOL_IPX:
		printxval(sock_ipx_options, name, "IPX_???");
		break;
	case SOL_AX25:
		printxval_search(sock_ax25_options, name, "AX25_???");
		break;
	case SOL_PACKET:
		printxval(sock_packet_options, name, "PACKET_???");
		break;
	case SOL_TCP:
		printxval_index(sock_tcp_options, name, "TCP_???");
		break;
	case SOL_SCTP:
		printxval(sock_sctp_options, name, "SCTP_???");
		break;
	case SOL_RAW:
		printxval(sock_raw_options, name, "RAW_???");
		break;
	case SOL_NETLINK:
		printxval(sock_netlink_options, name, "NETLINK_???");
		break;
	case SOL_UDP:
		printxval(sock_udp_options, name, "UDP_???");
		break;
	case SOL_IRDA:
		printxval_index(sock_irda_options, name, "IRLMP_???");
		break;
	case SOL_LLC:
		printxval_index(sock_llc_options, name, "LLC_OPT_???");
		break;
	case SOL_DCCP:
		printxval_search(sock_dccp_options, name, "DCCP_SOCKOPT_???");
		break;
	case SOL_TIPC:
		printxval_search(sock_tipc_options, name, "TIPC_???");
		break;
	case SOL_RXRPC:
		printxval_index(sock_rxrpc_options, name, "RXRPC_???");
		break;
	case SOL_PPPOL2TP:
		printxval_index(sock_pppol2tp_options, name, "PPPOL2TP_SO_???");
		break;
	case SOL_BLUETOOTH:
		printxval_search(sock_bluetooth_options, name, "BT_???");
		break;
	case SOL_PNPIPE:
		printxval(sock_pnp_options, name, "PNPIPE_???");
		break;
	case SOL_RDS:
		printxval_search(sock_rds_options, name, "RDS_???");
		break;
	case SOL_IUCV:
		printxval(sock_iucv_options, name, "SO_???");
		break;
	case SOL_CAIF:
		printxval(sock_caif_options, name, "CAIFSO_???");
		break;
	case SOL_ALG:
		printxval_index(sock_alg_options, name, "ALG_???");
		break;
	case SOL_NFC:
		printxval_index(sock_nfcllcp_options, name, "NFC_LLCP_???");
		break;
	case SOL_KCM:
		printxval(sock_kcm_options, name, "KCM_???");
		break;
	case SOL_TLS:
		printxval(sock_tls_options, name, "TLS_???");
		break;
	case SOL_XDP:
		printxval_index(sock_xdp_options, name, "XDP_???");
		break;

		/* Other SOL_* protocol levels still need work. */

	default:
		tprintf("%u", name);
	}

	tprints(", ");
}

static void
print_get_linger(struct tcb *const tcp, const kernel_ulong_t addr,
		 unsigned int len)
{
	struct linger linger;

	/*
	 * The kernel cannot return len > sizeof(linger) because struct linger
	 * cannot change, but extra safety won't harm either.
	 */
	if (len > sizeof(linger))
		len = sizeof(linger);
	if (umoven_or_printaddr(tcp, addr, len, &linger))
		return;

	if (len < sizeof(linger.l_onoff)) {
		tprints("{l_onoff=");
		print_quoted_string((void *) &linger.l_onoff,
				    len, QUOTE_FORCE_HEX);
	} else {
		PRINT_FIELD_D("{", linger, l_onoff);

		if (len > offsetof(struct linger, l_linger)) {
			len -= offsetof(struct linger, l_linger);
			if (len < sizeof(linger.l_linger)) {
				tprints(", l_linger=");
				print_quoted_string((void *) &linger.l_linger,
						    len, QUOTE_FORCE_HEX);
			} else {
				PRINT_FIELD_D(", ", linger, l_linger);
			}
		}
	}
	tprints("}");
}

static void
print_get_ucred(struct tcb *const tcp, const kernel_ulong_t addr,
		unsigned int len)
{
	struct ucred uc;

	/*
	 * The kernel is very unlikely to return len > sizeof(uc)
	 * because struct ucred is very unlikely to change,
	 * but extra safety won't harm either.
	 */
	if (len > sizeof(uc))
		len = sizeof(uc);

	if (umoven_or_printaddr(tcp, addr, len, &uc))
		return;

	if (len < sizeof(uc.pid)) {
		tprints("{pid=");
		print_quoted_string((void *) &uc.pid,
				    len, QUOTE_FORCE_HEX);
	} else {
		PRINT_FIELD_D("{", uc, pid);

		if (len > offsetof(struct ucred, uid)) {
			len -= offsetof(struct ucred, uid);
			if (len < sizeof(uc.uid)) {
				tprints(", uid=");
				print_quoted_string((void *) &uc.uid,
						    len, QUOTE_FORCE_HEX);
			} else {
				PRINT_FIELD_UID(", ", uc, uid);

				if (len > offsetof(struct ucred, gid) -
					  offsetof(struct ucred, uid)) {
					len -= offsetof(struct ucred, gid) -
					       offsetof(struct ucred, uid);
					if (len < sizeof(uc.gid)) {
						tprints(", gid=");
						print_quoted_string((void *) &uc.gid,
								    len,
								    QUOTE_FORCE_HEX);
					} else {
						PRINT_FIELD_UID(", ", uc, gid);
					}
				}
			}
		}
	}
	tprints("}");
}

#ifdef PACKET_STATISTICS
static void
print_tpacket_stats(struct tcb *const tcp, const kernel_ulong_t addr,
		    unsigned int len)
{
	struct tp_stats {
		unsigned int tp_packets, tp_drops, tp_freeze_q_cnt;
	} stats;

	/*
	 * The kernel may return len > sizeof(stats) if the kernel structure
	 * grew as it happened when tpacket_stats_v3 was introduced.
	 */
	if (len > sizeof(stats))
		len = sizeof(stats);

	if (umoven_or_printaddr(tcp, addr, len, &stats))
		return;

	if (len < sizeof(stats.tp_packets)) {
		tprints("{tp_packets=");
		print_quoted_string((void *) &stats.tp_packets,
				    len, QUOTE_FORCE_HEX);
	} else {
		PRINT_FIELD_U("{", stats, tp_packets);

		if (len > offsetof(struct tp_stats, tp_drops)) {
			len -= offsetof(struct tp_stats, tp_drops);
			if (len < sizeof(stats.tp_drops)) {
				tprints(", tp_drops=");
				print_quoted_string((void *) &stats.tp_drops,
						    len, QUOTE_FORCE_HEX);
			} else {
				PRINT_FIELD_U(", ", stats, tp_drops);

				if (len > offsetof(struct tp_stats, tp_freeze_q_cnt) -
					  offsetof(struct tp_stats, tp_drops)) {
					len -= offsetof(struct tp_stats, tp_freeze_q_cnt) -
					       offsetof(struct tp_stats, tp_drops);
					if (len < sizeof(stats.tp_freeze_q_cnt)) {
						tprints(", tp_freeze_q_cnt=");
						print_quoted_string((void *) &stats.tp_freeze_q_cnt,
								    len,
								    QUOTE_FORCE_HEX);
					} else {
						PRINT_FIELD_U(", ", stats, tp_freeze_q_cnt);
					}
				}
			}
		}
	}
	tprints("}");
}
#endif /* PACKET_STATISTICS */

#include "xlat/icmpfilterflags.h"

static void
print_icmp_filter(struct tcb *const tcp, const kernel_ulong_t addr, int len)
{
	struct icmp_filter filter = {};

	if (len > (int) sizeof(filter))
		len = sizeof(filter);
	else if (len <= 0) {
		printaddr(addr);
		return;
	}

	if (umoven_or_printaddr(tcp, addr, len, &filter))
		return;

	tprints("~(");
	printflags(icmpfilterflags, ~filter.data, "ICMP_???");
	tprints(")");
}

static void
print_getsockopt(struct tcb *const tcp, const unsigned int level,
		 const unsigned int name, const kernel_ulong_t addr,
		 const int ulen, const int rlen)
{
	if (ulen <= 0 || rlen <= 0) {
		/*
		 * As the kernel neither accepts nor returns a negative
		 * length in case of successful getsockopt syscall
		 * invocation, negative values must have been forged
		 * by userspace.
		 */
		printaddr(addr);
		return;
	}

	if (addr && verbose(tcp))
	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_LINGER:
			print_get_linger(tcp, addr, rlen);
			return;
		case SO_PEERCRED:
			print_get_ucred(tcp, addr, rlen);
			return;
		case SO_ATTACH_FILTER:
			/*
			 * The length returned by the kernel in case of
			 * successful getsockopt syscall invocation is struct
			 * sock_fprog.len that has type unsigned short,
			 * anything else must have been forged by userspace.
			 */
			if ((unsigned short) rlen == (unsigned int) rlen)
				print_sock_fprog(tcp, addr, rlen);
			else
				printaddr(addr);
			return;
		}
		break;

	case SOL_PACKET:
		switch (name) {
#ifdef PACKET_STATISTICS
		case PACKET_STATISTICS:
			print_tpacket_stats(tcp, addr, rlen);
			return;
#endif
		}
		break;

	case SOL_RAW:
		switch (name) {
		case ICMP_FILTER:
			print_icmp_filter(tcp, addr, rlen);
			return;
		}
		break;

	case SOL_NETLINK:
		switch (name) {
		case NETLINK_LIST_MEMBERSHIPS: {
			uint32_t buf;
			print_array(tcp, addr, MIN(ulen, rlen) / sizeof(buf),
				    &buf, sizeof(buf),
				    tfetch_mem, print_uint32_array_member, 0);
			break;
			}
		default:
			printnum_int(tcp, addr, "%d");
			break;
		}
		return;
	}

	/* default arg printing */

	if (verbose(tcp)) {
		if (rlen == sizeof(int)) {
			printnum_int(tcp, addr, "%d");
		} else {
			printstrn(tcp, addr, rlen);
		}
	} else {
		printaddr(addr);
	}
}

void print_arg_trace_getsockopt(struct tcb *tcp)
{
	printinvvar("sockfd", PRINT_LD, tcp->u_arg[0]);
	printinvvar("level", PRINT_LU, tcp->u_arg[1]);
	printinvvar("optname", PRINT_LU, tcp->u_arg[2]);
	printinvvar("optval", PRINT_ADDR, tcp->u_arg[3]);
	//optlen
	int optlen;
    if (umove(tcp, tcp->u_arg[4], &optlen) < 0){
        invprints("optlen\nnonsensical\n2\n");
    }
    else{
        printinvvar("optlen", PRINT_LU, optlen);
    };
}

#define  NUM_RET_GETSOCKOPT 3
INV_FUNC(getsockopt)
{
    static int *ibuf = NULL;
    static int vcount;
    static int num_ret = NUM_RET_GETSOCKOPT;
    tprintf("\nentering !!!!!!!!!!!!!!!\n");
	if (tcp->flags & TCB_INV_TRACE){
		if (entering(tcp)) {
			invprints("\n");
			invprints(ENTER_HEADER(getsockopt));
			invprintf("%d\n", count);
            print_arg_trace_getsockopt(tcp);
		} else {
			invprints("\n");
			invprints(EXIT_HEADER(getsockopt));
			invprintf("%d\n", count);
            print_arg_trace_getsockopt(tcp);
			printinvvar("return", PRINT_LD, tcp->u_rval);
		}
	}
	else if (tcp->flags & TCB_INV_TAMPER && !entering(tcp)){
		tprintf("\nentering2 !!!!!!!!!!!!!!!\n");
        if (ibuf == NULL){
            vcount = read_fuzz_file(FUZZ_FILE(getsockopt), &ibuf, num_ret);
        }
        tprintf("\nvcount:%d !!!!!!!!!!!!!!!, count:%d, %d\n", vcount, count, vcount >= 0 && count >= vcount);
        if (vcount >= 0 && count >= vcount){
			tprintf("\nentering3 !!!!!!!!!!!!!!!\n");
            socklen_t ulen, rlen;
            ulen = get_tcb_priv_ulong(tcp);
            kernel_long_t ret = tcp->u_rval;
            void *buf = malloc(ulen);

            tfetch_mem(tcp, tcp->u_arg[3], ulen, buf);
            tfetch_mem(tcp, tcp->u_arg[4], sizeof(socklen_t), &rlen);

            tprintf("\noriginal rlen: %d -> ", rlen);
            /* tamper code accept */
            m_set mlist[NUM_RET_GETSOCKOPT] = {{buf, ulen, VARIABLE_NORMAL},\
										{&rlen, sizeof(socklen_t), VARIABLE_NORMAL},\
                                        {&ret, sizeof(int), VARIABLE_FD}};
            fuzzing_return_value(ibuf, mlist, num_ret);
            tprintf("%d\n", rlen);
            if (ibuf[2] == 1){
                tprintf("\nmodified return: %ld \n", ret);
                tcp->ret_modified = 1;
            }


            /* end of temper code accept */
            /* write back data to tracee and clean up */
            vm_write_mem(tcp->pid, buf, tcp->u_arg[3], ulen);
            vm_write_mem(tcp->pid, &rlen, tcp->u_arg[4], sizeof(socklen_t));
            tcp->u_rval = ret;
            free(buf);
        }

	}
}

SYS_FUNC(getsockopt)
{
	int ulen, rlen;

	if (entering(tcp)) {
		print_sockopt_fd_level_name(tcp, tcp->u_arg[0],
					    tcp->u_arg[1], tcp->u_arg[2], true);

		if (verbose(tcp) && tcp->u_arg[4]
		    && umove(tcp, tcp->u_arg[4], &ulen) == 0) {
			set_tcb_priv_ulong(tcp, ulen);
			return 0;
		} else {
			printaddr(tcp->u_arg[3]);
			tprints(", ");
			printaddr(tcp->u_arg[4]);
			return RVAL_DECODED;
		}
	} else {
		ulen = get_tcb_priv_ulong(tcp);

		if (syserror(tcp) || umove(tcp, tcp->u_arg[4], &rlen) < 0) {
			printaddr(tcp->u_arg[3]);
			tprintf(", [%d]", ulen);
		} else {
			print_getsockopt(tcp, tcp->u_arg[1], tcp->u_arg[2],
					 tcp->u_arg[3], ulen, rlen);
			if (ulen != rlen)
				tprintf(", [%d->%d]", ulen, rlen);
			else
				tprintf(", [%d]", rlen);
		}
	}
	return 0;
}

static void
print_set_linger(struct tcb *const tcp, const kernel_ulong_t addr,
		 const int len)
{
	struct linger linger;

	if (len < (int) sizeof(linger)) {
		printaddr(addr);
	} else if (!umove_or_printaddr(tcp, addr, &linger)) {
		PRINT_FIELD_D("{", linger, l_onoff);
		PRINT_FIELD_D(", ", linger, l_linger);
		tprints("}");
	}
}

#ifdef IP_ADD_MEMBERSHIP
static void
print_mreq(struct tcb *const tcp, const kernel_ulong_t addr,
	   const int len)
{
	struct ip_mreq mreq;

	if (len < (int) sizeof(mreq)) {
		printaddr(addr);
	} else if (!umove_or_printaddr(tcp, addr, &mreq)) {
		PRINT_FIELD_INET4_ADDR("{", mreq, imr_multiaddr);
		PRINT_FIELD_INET4_ADDR(", ", mreq, imr_interface);
		tprints("}");
	}
}
#endif /* IP_ADD_MEMBERSHIP */

#ifdef IPV6_ADD_MEMBERSHIP
static void
print_mreq6(struct tcb *const tcp, const kernel_ulong_t addr,
	    const int len)
{
	struct ipv6_mreq mreq;

	if (len < (int) sizeof(mreq)) {
		printaddr(addr);
	} else if (!umove_or_printaddr(tcp, addr, &mreq)) {
		PRINT_FIELD_INET_ADDR("{", mreq, ipv6mr_multiaddr, AF_INET6);
		PRINT_FIELD_IFINDEX(", ", mreq, ipv6mr_interface);
		tprints("}");
	}
}
#endif /* IPV6_ADD_MEMBERSHIP */

#ifdef PACKET_RX_RING
static void
print_tpacket_req(struct tcb *const tcp, const kernel_ulong_t addr, const int len)
{
	struct tpacket_req req;

	if (len != sizeof(req) ||
	    umove(tcp, addr, &req) < 0) {
		printaddr(addr);
	} else {
		PRINT_FIELD_U("{", req, tp_block_size);
		PRINT_FIELD_U(", ", req, tp_block_nr);
		PRINT_FIELD_U(", ", req, tp_frame_size);
		PRINT_FIELD_U(", ", req, tp_frame_nr);
		tprints("}");
	}
}
#endif /* PACKET_RX_RING */

#ifdef PACKET_ADD_MEMBERSHIP
# include "xlat/packet_mreq_type.h"

static void
print_packet_mreq(struct tcb *const tcp, const kernel_ulong_t addr, const int len)
{
	struct packet_mreq mreq;

	if (len != sizeof(mreq) ||
	    umove(tcp, addr, &mreq) < 0) {
		printaddr(addr);
	} else {
		unsigned int i;

		PRINT_FIELD_IFINDEX("{", mreq, mr_ifindex);
		PRINT_FIELD_XVAL(", ", mreq, mr_type, packet_mreq_type,
				 "PACKET_MR_???");
		PRINT_FIELD_U(", ", mreq, mr_alen);
		tprints(", mr_address=");
		if (mreq.mr_alen > ARRAY_SIZE(mreq.mr_address))
			mreq.mr_alen = ARRAY_SIZE(mreq.mr_address);
		for (i = 0; i < mreq.mr_alen; ++i)
			tprintf("%02x", mreq.mr_address[i]);
		tprints("}");
	}
}
#endif /* PACKET_ADD_MEMBERSHIP */

static void
print_setsockopt(struct tcb *const tcp, const unsigned int level,
		 const unsigned int name, const kernel_ulong_t addr,
		 const int len)
{
	if (addr && verbose(tcp))
	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_LINGER:
			print_set_linger(tcp, addr, len);
			return;
		case SO_ATTACH_FILTER:
		case SO_ATTACH_REUSEPORT_CBPF:
			if ((unsigned int) len == get_sock_fprog_size())
				decode_sock_fprog(tcp, addr);
			else
				printaddr(addr);
			return;
		}
		break;

	case SOL_IP:
		switch (name) {
#ifdef IP_ADD_MEMBERSHIP
		case IP_ADD_MEMBERSHIP:
		case IP_DROP_MEMBERSHIP:
			print_mreq(tcp, addr, len);
			return;
#endif /* IP_ADD_MEMBERSHIP */
#ifdef MCAST_JOIN_GROUP
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
			print_group_req(tcp, addr, len);
			return;
#endif /* MCAST_JOIN_GROUP */
		}
		break;

	case SOL_IPV6:
		switch (name) {
#ifdef IPV6_ADD_MEMBERSHIP
		case IPV6_ADD_MEMBERSHIP:
		case IPV6_DROP_MEMBERSHIP:
# ifdef IPV6_JOIN_ANYCAST
		case IPV6_JOIN_ANYCAST:
# endif
# ifdef IPV6_LEAVE_ANYCAST
		case IPV6_LEAVE_ANYCAST:
# endif
			print_mreq6(tcp, addr, len);
			return;
#endif /* IPV6_ADD_MEMBERSHIP */
#ifdef MCAST_JOIN_GROUP
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
			print_group_req(tcp, addr, len);
			return;
#endif /* MCAST_JOIN_GROUP */
		}
		break;

	case SOL_PACKET:
		switch (name) {
#ifdef PACKET_RX_RING
		case PACKET_RX_RING:
# ifdef PACKET_TX_RING
		case PACKET_TX_RING:
# endif
			print_tpacket_req(tcp, addr, len);
			return;
#endif /* PACKET_RX_RING */
#ifdef PACKET_ADD_MEMBERSHIP
		case PACKET_ADD_MEMBERSHIP:
		case PACKET_DROP_MEMBERSHIP:
			print_packet_mreq(tcp, addr, len);
			return;
#endif /* PACKET_ADD_MEMBERSHIP */
		}
		break;

	case SOL_RAW:
		switch (name) {
		case ICMP_FILTER:
			print_icmp_filter(tcp, addr, len);
			return;
		}
		break;

	case SOL_NETLINK:
		if (len < (int) sizeof(int))
			printaddr(addr);
		else
			printnum_int(tcp, addr, "%d");
		return;
	}

	/* default arg printing */

	if (verbose(tcp)) {
		if (len == sizeof(int)) {
			printnum_int(tcp, addr, "%d");
		} else {
			printstrn(tcp, addr, len);
		}
	} else {
		printaddr(addr);
	}
}

SYS_FUNC(setsockopt)
{
	print_sockopt_fd_level_name(tcp, tcp->u_arg[0],
				    tcp->u_arg[1], tcp->u_arg[2], false);
	print_setsockopt(tcp, tcp->u_arg[1], tcp->u_arg[2],
			 tcp->u_arg[3], tcp->u_arg[4]);
	tprintf(", %d", (int) tcp->u_arg[4]);

	return RVAL_DECODED;
}
