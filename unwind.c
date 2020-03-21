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

#ifdef USE_DEMANGLE
# if defined HAVE_DEMANGLE_H
#  include <demangle.h>
# elif defined HAVE_LIBIBERTY_DEMANGLE_H
#  include <libiberty/demangle.h>
# endif
#endif

char stack_buf[4096];

/* murmur hash in c, copied from wikipedia */
static inline uint32_t murmur_32_scramble(uint32_t k) {
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    return k;
}
uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed)
{
    uint32_t h = seed;
    uint32_t k;
    /* Read in groups of 4. */
    for (size_t i = len >> 2; i; i--) {
        // Here is a source of differing results across endiannesses.
        // A swap here has no effects on hash properties though.
        k = *((uint32_t*)key);
        key += sizeof(uint32_t);
        h ^= murmur_32_scramble(k);
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xe6546b64;
    }
    /* Read the rest. */
    k = 0;
    for (size_t i = len & 3; i; i--) {
        k <<= 8;
        k |= key[i - 1];
    }
    // A swap is *not* necessary here because the preceeding loop already
    // places the low bytes in the low places according to whatever endianness
    // we use. Swaps only apply when the memory is copied in a chunk.
    h ^= murmur_32_scramble(k);
    /* Finalize. */
    h ^= len;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

/*
 * Type used in stacktrace capturing
 */
struct call_t {
	struct call_t *next;
	char *output_line;
};

struct unwind_queue_t {
	struct call_t *tail;
	struct call_t *head;
};

static void queue_print(struct unwind_queue_t *queue);

static const char asprintf_error_str[] = "???";

void
unwind_init(void)
{
	if (unwinder.init)
		unwinder.init();
}

void
unwind_tcb_init(struct tcb *tcp)
{
	if (tcp->unwind_queue)
		return;

	tcp->unwind_queue = xmalloc(sizeof(*tcp->unwind_queue));
	tcp->unwind_queue->head = NULL;
	tcp->unwind_queue->tail = NULL;

	tcp->unwind_ctx = unwinder.tcb_init(tcp);
}

void
unwind_tcb_fin(struct tcb *tcp)
{
	if (!tcp->unwind_queue)
		return;

	queue_print(tcp->unwind_queue);
	free(tcp->unwind_queue);
	tcp->unwind_queue = NULL;

	unwinder.tcb_fin(tcp);
	tcp->unwind_ctx = NULL;
}

/*
 * printing an entry in stack to stream or buffer
 */
/*
 * we want to keep the format used by backtrace_symbols from the glibc
 *
 * ./a.out() [0x40063d]
 * ./a.out() [0x4006bb]
 * ./a.out() [0x4006c6]
 * /lib64/libc.so.6(__libc_start_main+0xed) [0x7fa2f8a5976d]
 * ./a.out() [0x400569]
 */
#define STACK_ENTRY_SYMBOL_FMT(SYM)		\
	" > %s(%s+0x%lx) [0x%lx]\n",		\
	binary_filename,			\
	(SYM),					\
	(unsigned long) function_offset,	\
	true_offset
#define STACK_ENTRY_NOSYMBOL_FMT		\
	" > %s() [0x%lx]\n",			\
	binary_filename, true_offset
#define STACK_ENTRY_BUG_FMT			\
	" > BUG IN %s\n"
#define STACK_ENTRY_ERROR_WITH_OFFSET_FMT	\
	" > %s [0x%lx]\n", error, true_offset
#define STACK_ENTRY_ERROR_FMT			\
	" > %s\n", error

static void
print_call_cb(void *dummy,
	      const char *binary_filename,
	      const char *symbol_name,
	      unwind_function_offset_t function_offset,
	      unsigned long true_offset)
{
	if (symbol_name && (symbol_name[0] != '\0')) {
#ifdef USE_DEMANGLE
		char *demangled_name =
			cplus_demangle(symbol_name,
				       DMGL_AUTO | DMGL_PARAMS);
#endif
		tprintf(STACK_ENTRY_SYMBOL_FMT(
#ifdef USE_DEMANGLE
					       demangled_name ? demangled_name :
#endif
					       symbol_name));
#ifdef USE_DEMANGLE
		free(demangled_name);
#endif
	}
	else if (binary_filename)
		tprintf(STACK_ENTRY_NOSYMBOL_FMT);
	else
		tprintf(STACK_ENTRY_BUG_FMT, __func__);

	line_ended();
}

static void
output_call_cb(void *dummy,
              const char *binary_filename,
              const char *symbol_name,
              unwind_function_offset_t function_offset,
              unsigned long true_offset)
{
    char tmp[1024];
    strcpy(tmp,  "");

    if (symbol_name && (symbol_name[0] != '\0')) {
#ifdef USE_DEMANGLE
        char *demangled_name =
			cplus_demangle(symbol_name,
				       DMGL_AUTO | DMGL_PARAMS);
#endif
        sprintf(tmp, STACK_ENTRY_SYMBOL_FMT(
#ifdef USE_DEMANGLE
                demangled_name ? demangled_name :
#endif
                symbol_name));
#ifdef USE_DEMANGLE
        free(demangled_name);
#endif
    }
    else if (binary_filename) {
        sprintf(tmp, STACK_ENTRY_NOSYMBOL_FMT);
    }

    else
    {
        sprintf(tmp, STACK_ENTRY_BUG_FMT, __func__);
    }

    strcat(stack_buf, tmp);
}

static void
print_error_cb(void *dummy,
	       const char *error,
	       unsigned long true_offset)
{
	if (true_offset)
		tprintf(STACK_ENTRY_ERROR_WITH_OFFSET_FMT);
	else
		tprintf(STACK_ENTRY_ERROR_FMT);

	line_ended();
}

static char *
sprint_call_or_error(const char *binary_filename,
		     const char *symbol_name,
		     unwind_function_offset_t function_offset,
		     unsigned long true_offset,
		     const char *error)
{
	char *output_line = NULL;
	int n;

	if (symbol_name) {
#ifdef USE_DEMANGLE
		char *demangled_name =
			cplus_demangle(symbol_name,
				       DMGL_AUTO | DMGL_PARAMS);
#endif
		n = asprintf(&output_line,
			     STACK_ENTRY_SYMBOL_FMT(
#ifdef USE_DEMANGLE
						    demangled_name ? demangled_name :
#endif
						    symbol_name));
#ifdef USE_DEMANGLE
		free(demangled_name);
#endif
	}
	else if (binary_filename)
		n = asprintf(&output_line, STACK_ENTRY_NOSYMBOL_FMT);
	else if (error)
		n = true_offset
			? asprintf(&output_line, STACK_ENTRY_ERROR_WITH_OFFSET_FMT)
			: asprintf(&output_line, STACK_ENTRY_ERROR_FMT);
	else
		n = asprintf(&output_line, STACK_ENTRY_BUG_FMT, __func__);

	if (n < 0) {
		perror_func_msg("asprintf");
		output_line = (char *) asprintf_error_str;
	}

	return output_line;
}

/*
 * queue manipulators
 */
static void
queue_put(struct unwind_queue_t *queue,
	  const char *binary_filename,
	  const char *symbol_name,
	  unwind_function_offset_t function_offset,
	  unsigned long true_offset,
	  const char *error)
{
	struct call_t *call;

	call = xmalloc(sizeof(*call));
	call->output_line = sprint_call_or_error(binary_filename,
						 symbol_name,
						 function_offset,
						 true_offset,
						 error);
	call->next = NULL;

	if (!queue->head) {
		queue->head = call;
		queue->tail = call;
	} else {
		queue->tail->next = call;
		queue->tail = call;
	}
}

static void
queue_put_call(void *queue,
	       const char *binary_filename,
	       const char *symbol_name,
	       unwind_function_offset_t function_offset,
	       unsigned long true_offset)
{
	queue_put(queue,
		  binary_filename,
		  symbol_name,
		  function_offset,
		  true_offset,
		  NULL);
}

static void
queue_put_error(void *queue,
		const char *error,
		unsigned long ip)
{
	queue_put(queue, NULL, NULL, 0, ip, error);
}

static void
queue_output(struct unwind_queue_t *queue, bool print)
{
	struct call_t *call, *tmp;

	queue->tail = NULL;
	call = queue->head;
	queue->head = NULL;
    strcpy(stack_buf,  "");

	while (call) {
		tmp = call;
		call = call->next;
        if (print) {
            tprints(tmp->output_line);
            line_ended();
        }
        else {
            strcat(stack_buf, tmp->output_line);
        }
		if (tmp->output_line != asprintf_error_str)
			free(tmp->output_line);

		tmp->output_line = NULL;
		tmp->next = NULL;
		free(tmp);
	}
}

static void
queue_print(struct unwind_queue_t *queue)
{
    queue_output(queue, true);
}

/*
 * printing stack
 */
void
unwind_tcb_output(struct tcb *tcp, bool print)
{
#if SUPPORTED_PERSONALITIES > 1
	if (tcp->currpers != DEFAULT_PERSONALITY) {
		/* disable stack trace */
		return;
	}
#endif
    strcpy(stack_buf, "");
	if (tcp->unwind_queue->head) {
		debug_func_msg("head: tcp=%p, queue=%p",
			       tcp, tcp->unwind_queue->head);

		queue_output(tcp->unwind_queue, print);

	} else {
	    if (print){
            unwinder.tcb_walk(tcp, print_call_cb, print_error_cb, NULL);
	    }
        else {

            unwinder.tcb_walk(tcp, output_call_cb, print_error_cb, NULL);
        }
	}
	if (!print)
    {
        uint32_t hash = murmur3_32((const uint8_t*)stack_buf, strlen(stack_buf), 2333);
        if (cov_file != NULL)
        {
            // append the syscall to record file
            FILE* fptr = fopen(cov_file, "a+");
            fprintf(fptr, "%s: %u\n", tcp->s_ent->sys_name, hash);
            fclose(fptr);
        }
    }

}

void
unwind_tcb_print(struct tcb *tcp)
{
    unwind_tcb_output(tcp, true);
}
/*
 * capturing stack
 */
void
unwind_tcb_capture(struct tcb *tcp)
{
#if SUPPORTED_PERSONALITIES > 1
	if (tcp->currpers != DEFAULT_PERSONALITY) {
		/* disable stack trace */
		return;
	}
#endif
	if (tcp->unwind_queue->head)
		error_msg_and_die("bug: unprinted entries in queue");
	else {
		debug_func_msg("walk: tcp=%p, queue=%p",
			       tcp, tcp->unwind_queue->head);
		unwinder.tcb_walk(tcp, queue_put_call, queue_put_error,
				  tcp->unwind_queue);
	}
}
