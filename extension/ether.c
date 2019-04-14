/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)if_ether.h	8.3 (Berkeley) 5/2/95
 */

#include <stdint.h>

#define	ETHERMTU	1500

/*
 * The number of bytes in an ethernet (MAC) address.
 */
#define	ETHER_ADDR_LEN		6

/*
 * Structure of an Ethernet header.
 */
struct	ether_header {
	uint8_t		ether_dhost[ETHER_ADDR_LEN];
	uint8_t		ether_shost[ETHER_ADDR_LEN];
	uint16_t	ether_length_type;
};

/*
 * Length of an Ethernet header; note that some compilers may pad
 * "struct ether_header" to a multiple of 4 bytes, for example, so
 * "sizeof (struct ether_header)" may not give the right answer.
 */
#define ETHER_HDRLEN		14

/* ====================== End of Berkeley code ===================== */

#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ether.h>

static struct net_field *
get_ether_dst_addr(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ether_src_addr(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ether_type(const u_char *buf, size_t buf_len, void *ctx);

struct net_field_descriptor ether_fields[] = {
	{.name = "dst_addr", .field_func = get_ether_dst_addr},
	{.name = "src_addr", .field_func = get_ether_src_addr},
	{.name = "type", .field_func = get_ether_type},
};


struct protocol_descriptor ether_protocol = {
	.name =  "Ethernet",
	.fields = ether_fields,
	.ctx = NULL,
	.init = NULL,
	.clean = NULL,
};

static struct net_field *
get_ether_dst_addr(const u_char* buf, size_t buf_len, void* ctx)
{
	struct ether_header *eh;
	INIT_NET_FIELD(nf);
	
	char *dst_addr = (char *)malloc(18);
	if (NULL == dst_addr)
		do_fatal("can not allocate Ethernet destination address");
	
        if (buf_len < ETHER_HDRLEN) {
	        free(dst_addr);
	        return NULL;
	}
    
        eh = (struct ether_header *)buf;
        snprintf(dst_addr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
		eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
	
	nf->val.s_val = dst_addr;
	nf->val.n_val = 17;
	nf->type = awk_str_t;
	
	return nf;
}

static struct net_field *
get_ether_src_addr(const u_char* buf, size_t buf_len, void* ctx)
{
        struct ether_header *eh;
	INIT_NET_FIELD(nf);
	
	char *src_addr = (char *)malloc(18);
	if (NULL == src_addr)
		do_fatal("can not allocate Ethernet source address");
	
	if (buf_len < ETHER_HDRLEN) {
	        free(src_addr);
		return NULL;
	}
	
	eh = (struct ether_header *)buf;
	snprintf(src_addr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2],
		eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);
	
	nf->val.s_val = src_addr;
	nf->val.n_val = 17;
	nf->type = awk_str_t;
	
	return nf;
}

static struct net_field *
get_ether_type(const u_char* buf, size_t buf_len, void* ctx)
{
        struct ether_header *eh;
	INIT_NET_FIELD(nf);
	
	if (buf_len < ETHER_HDRLEN) {
		return NULL;
	}
	
	eh = (struct ether_header *)buf;
	nf->val.n_val = ntohs(eh->ether_length_type);
	nf->type = awk_numbr_t;
	
	return nf;
}
