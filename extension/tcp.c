// Below is a modified version of TCP header defintion from the Linux source
// code with its original license header comments.

/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

struct tcp {
	uint16_t	source;
	uint16_t	dest;
	uint32_t	seq;
	uint32_t	ack_seq;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint16_t ns:1,	
	  res1:3,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#endif
#if BYTE_ORDER == BIG_ENDIAN
	uint16_t	doff:4,
		res1:3,
		ns:1,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#endif
	uint16_t	window;
	uint16_t	check;
	uint16_t	urg_ptr;
};

//=============== End of the Linux source code ==============

#include <tcp.h>

static struct net_field *
get_tcp_source_port(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_dst_port(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_seq(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_ack_seq(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_ns(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_resv(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_doff(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_fin(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_syn(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_rst(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_psh(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_ack(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_urg(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_ece(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_cwr(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_win(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_chk(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_tcp_urg_ptr(const u_char *buf, size_t buf_len, ...);


static struct net_field_descriptor tcp_fields[] = {
  {.name = "src_port", .is_regex = false, .field_func = get_tcp_source_port},
  {.name = "dst_port", .is_regex = false, .field_func = get_tcp_dst_port},
  {.name = "seq", .is_regex = false, .field_func = get_tcp_seq},
  {.name = "ackno", .is_regex = false, .field_func = get_tcp_ack_seq},
  {.name = "resv", .is_regex = false, .field_func = get_tcp_resv},
  {.name = "doff", .is_regex = false, .field_func = get_tcp_doff},
  {.name = "fin", .is_regex = false, .field_func = get_tcp_fin},
  {.name = "syn", .is_regex = false, .field_func = get_tcp_syn},
  {.name = "rst", .is_regex = false, .field_func = get_tcp_rst},
  {.name = "psh", .is_regex = false, .field_func = get_tcp_psh},
  {.name = "ack", .is_regex = false, .field_func = get_tcp_ack},
  {.name = "urg", .is_regex = false, .field_func = get_tcp_urg},
  {.name = "ece", .is_regex = false, .field_func = get_tcp_ece},
  {.name = "cwr", .is_regex = false, .field_func = get_tcp_cwr},
  {.name = "ns", .is_regex = false, .field_func = get_tcp_ns},
  {.name = "cwin", .is_regex = false, .field_func = get_tcp_win},
  {.name = "chk", .is_regex = false, .field_func = get_tcp_chk},
  {.name = "urg_ptr", .is_regex = false, .field_func = get_tcp_urg_ptr},
  {.name = NULL, .field_func = NULL}
};

static int tcp_proto_init(const u_char *buf, size_t buf_size);

struct protocol_descriptor tcp_protocol = {
  .name =  "TCP",
  .fields = tcp_fields,
  .init = tcp_proto_init,
  .clean = NULL
};

#define MAX_TCP_HEADER_LEN 60
#define MIN_TCP_HEADER_LEN 20

static int tcp_proto_init(const u_char *buf, size_t buf_size)
{
  if (buf_size < MIN_TCP_HEADER_LEN) {
    return -1;
  }

  struct tcp *header = (struct tcp *)buf;

  // Check that the reserved field is 0
  if (header->res1 != 0) {
    return -1;
  }
  
  INIT_NET_FIELD(nf);
  nf = get_tcp_doff(buf, buf_size);
  if (nf == NULL) {
    return -1;
  } else {
    int res = (int)nf->num_val * 4;
    free(nf);
    return res;
  }
}

#define CHK_TCP_BUF_LEN(buf_len) \
  do {\
    if ((buf_len) < MIN_TCP_HEADER_LEN) {\
      do_fatal("not enougth buffered data for TCP header: "\
	            "expect at least %d bytes, have %d bytes",\
		    MIN_TCP_HEADER_LEN, (buf_len));\
    }\
  } while(0)

static struct net_field *
get_tcp_source_port(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = ntohs(hdr->source);
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_dst_port(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = ntohs(hdr->dest);
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_seq(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = ntohl(hdr->seq);
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_ack_seq(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = ntohl(hdr->ack_seq);
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_ns(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = hdr->ns;
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_resv(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = hdr->res1;
  nf->type = awk_numbr_t;

  return nf;
}


static struct net_field *
get_tcp_doff(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = hdr->doff;
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_fin(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = hdr->fin;
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_syn(const u_char *buf, size_t buf_len, ...)
{
   CHK_TCP_BUF_LEN(buf_len);

   struct tcp *hdr = (struct tcp *)buf;
   INIT_NET_FIELD(nf);

   nf->num_val = hdr->syn;
   nf->type = awk_numbr_t;

   return nf;
}

static struct net_field *
get_tcp_rst(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = hdr->rst;
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_psh(const u_char *buf, size_t buf_len, ...)
{
   CHK_TCP_BUF_LEN(buf_len);

   struct tcp *hdr = (struct tcp *)buf;
   INIT_NET_FIELD(nf);

   nf->num_val = hdr->psh;
   nf->type = awk_numbr_t;

   return nf;
}

static struct net_field *
get_tcp_ack(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = hdr->ack;
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_urg(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = hdr->urg;
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_ece(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = hdr->ece;
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_cwr(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = hdr->cwr;
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_win(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = ntohs(hdr->window);
  nf->type = awk_numbr_t;

  return nf;

}
static struct net_field *
get_tcp_chk(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = ntohs(hdr->check);
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field *
get_tcp_urg_ptr(const u_char *buf, size_t buf_len, ...)
{
  CHK_TCP_BUF_LEN(buf_len);

  struct tcp *hdr = (struct tcp *)buf;
  INIT_NET_FIELD(nf);

  nf->num_val = ntohs(hdr->urg_ptr);
  nf->type = awk_numbr_t;

  return nf;
}
