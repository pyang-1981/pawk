/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
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
 *	@(#)ip.h	7.10 (Berkeley) 6/28/90
 */

#include <arpa/inet.h>

/*
 * Definitions for internet protocol version 4.
 * Per RFC 791, September 1981.
 */
#define	IPVERSION	4

/*
 * Structure of an internet header, naked of options.
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN 
        u_char	ip_hl:4,		/* header length */
	                ip_v:4;		/* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
	u_char	ip_v:4,			/* version */
		        ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
        short        ip_flags:3,               /* IPv4 flags*/
	                ip_off:13;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

#define	IP_MAXPACKET	65535		/* maximum packet size */

/* ==========End of Berkeley code ========= */

#include <stdio.h>
#include <stdlib.h>
#include <ip.h>

static struct net_field *
get_ipv4_dst_addr(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_src_addr(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_hdr_len(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_ver(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_tos(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_len(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_id(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_offset(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_ttl(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_ttl(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_proto(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_csum(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_ipv4_payload(const u_char *buf, size_t buf_len, void *ctx);

static struct net_field_descriptor ipv4_fields[] = {
	{.name = "dst_addr", .field_func = get_ipv4_dst_addr},
	{.name = "src_addr", .field_func = get_ipv4_src_addr},
        {.name = "hdr_len", .field_func = get_ipv4_hdr_len},
	{.name = "ver", .field_func = get_ipv4_ver},
	{.name = "tos", .field_func = get_ipv4_tos},
	{.name = "len", .field_func = get_ipv4_len},
	{.name = "id", .field_func = get_ipv4_id},
	{.name = "offset", .field_func = get_ipv4_offset},
	{.name = "ttl", .field_func = get_ipv4_ttl},
	{.name = "proto", .field_func = get_ipv4_proto},
	{.name = "csum", .field_func = get_ipv4_csum},
	{.name = "payload", .field_func = get_ipv4_payload}
};

static void ipv4_proto_init(const u_char **buf, unsigned int *buf_size,
				void *ctx);

struct protocol_descriptor ipv4_protocol = {
	.name =  "IPv4",
	.fields = ipv4_fields,
	.ctx = NULL,
	.init = ipv4_proto_init,
	.clean = NULL,
};

#define IPV4_MIN_HDR_LEN 20

void
ipv4_proto_init(const u_char **buf, unsigned int *buf_size, void *ctx)
{
        struct ip *header = (struct ip *)(*buf);
    
        // Check that the version is 4.
	if (header->ip_v != 4) {
	    *buf = NULL; // Signal initialization error.
            return;
	}

	if (*buf_size < IPV4_MIN_HDR_LEN) {
            *buf = NULL;
	    return;
	}

	// Determine the header length.
	*buf_size = (header->ip_hl << 2);
}

/*
 * IPv4 address representation length, i.e, the length of
 * "xxx.xxx.xxx.xxx".
 */
#define IPV4_ADDR_REPR_LEN 16

struct net_field *
get_ipv4_dst_addr(const u_char* buf, size_t buf_len, void* ctx)
{
	struct ip *header;
	INIT_NET_FIELD(nf);
	
	char *dst_addr = (char *)malloc(IPV4_ADDR_REPR_LEN);
	if (NULL == dst_addr)
		do_fatal("can not allocate IPv4 destination address");
    
        header = (struct ip *)buf;
        if (inet_ntop(AF_INET, &header->ip_dst.s_addr,dst_addr,
		      IPV4_ADDR_REPR_LEN) == NULL) {
	    free(dst_addr);
	    return NULL;
	}

	nf->val.s_val = dst_addr;
	nf->val.n_val =IPV4_ADDR_REPR_LEN - 1 ;
	nf->type = awk_str_t;
	
	return nf;
}

struct net_field *
get_ipv4_src_addr(const u_char  *buf, size_t buf_len, void *ctx)
{
        struct ip *header;
	INIT_NET_FIELD(nf);
	
	char *src_addr = (char *)malloc(IPV4_ADDR_REPR_LEN);
	if (NULL == src_addr)
		do_fatal("can not allocate IPv4 source address");
    
        header = (struct ip *)buf;
        if (inet_ntop(AF_INET, &header->ip_src.s_addr, src_addr,
		      IPV4_ADDR_REPR_LEN) == NULL) {
	    free(src_addr);
	    return NULL;
	}

	nf->val.s_val = src_addr;
	nf->val.n_val =IPV4_ADDR_REPR_LEN - 1 ;
	nf->type = awk_str_t;
	
	return nf;
}

struct net_field *
get_ipv4_hdr_len(const u_char *buf, size_t buf_len, void *ctx)
{
        struct ip *header = (struct ip *)buf;
        INIT_NET_FIELD(nf);

        nf->type = awk_numbr_t;
        nf->val.n_val = buf_len;

        return nf;
}

struct net_field *
get_ipv4_ver(const u_char *buf, size_t buf_len, void *ctx)
{
        struct ip *header = (struct ip *)buf;
        INIT_NET_FIELD(nf);

        nf->type = awk_numbr_t;
        nf->val.n_val = header->ip_v;

        return nf;
}

struct net_field *
get_ipv4_tos(const u_char *buf, size_t buf_len, void *ctx)
{
        struct ip *header = (struct ip *)buf;
        INIT_NET_FIELD(nf);

        nf->type = awk_numbr_t;
        nf->val.n_val = header->ip_tos;

        return nf;
}

struct net_field *
get_ipv4_len(const u_char *buf, size_t buf_len, void *ctx)
{
        struct ip *header = (struct ip *)buf;
        INIT_NET_FIELD(nf);

        nf->type = awk_numbr_t;
        nf->val.n_val = header->ip_len;

        return nf;
}

struct net_field *
get_ipv4_id(const u_char *buf, size_t buf_len, void *ctx)
{
        struct ip *header = (struct ip *)buf;
        INIT_NET_FIELD(nf);

        nf->type = awk_numbr_t;
        nf->val.n_val = header->ip_id;

        return nf;
}

struct net_field *
get_ipv4_offset(const u_char *buf, size_t buf_len, void *ctx)
{
        struct ip *header = (struct ip *)buf;
        INIT_NET_FIELD(nf);

        nf->type = awk_numbr_t;
        nf->val.n_val = (header->ip_off << 3);

	return nf;
}

struct net_field *
get_ipv4_ttl(const u_char *buf, size_t buf_len, void *ctx)
{
        struct ip *header = (struct ip *)buf;
        INIT_NET_FIELD(nf);

        nf->type = awk_numbr_t;
        nf->val.n_val = header->ip_ttl;

        return nf;
}

struct net_field *
get_ipv4_proto(const u_char *buf, size_t buf_len, void *ctx)
{
        struct ip *header = (struct ip *)buf;
        INIT_NET_FIELD(nf);

        nf->type = awk_numbr_t;
        nf->val.n_val = header->ip_p;

        return nf;
}

struct net_field *
get_ipv4_csum(const u_char *buf, size_t buf_len, void *ctx)
{
        struct ip *header = (struct ip *)buf;
        INIT_NET_FIELD(nf);

        nf->type = awk_numbr_t;
        nf->val.n_val = header->ip_sum;

        return nf;
}

struct net_field *
get_ipv4_payload(const u_char *buf, size_t buf_len, void *ctx)
{
        struct ip *header = (struct ip *)buf;
        INIT_NET_FIELD(nf);

        nf->type = awk_bin_t;
        nf->val.s_val = (char *)(buf + (header->ip_hl << 2));
        nf->val.n_val = buf_len - (header->ip_hl << 2);

        return nf;
}



