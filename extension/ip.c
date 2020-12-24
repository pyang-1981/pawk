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

#include <stdint.h>
#include <arpa/inet.h>

/*
 * Definitions for Internet protocol version 4.
 * Per RFC 791, September 1981.
 */
#define	IPVERSION	4

/*
 * Structure of an Internet header, naked of options.
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct ip {
#if BYTE_ORDER == LITTLE_ENDIAN 
  u_char	ip_hl:4,		/* header length */
	        ip_v:4;		        /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
  u_char	ip_v:4,			/* version */
          ip_hl:4;		/* header length */
#endif
  u_char	ip_tos;			/* type of service */
  u_short	ip_len;			/* total length */
  u_short	ip_id;			/* identification */
  u_short       ip_off;                 /* IPv4 flags & offset*/
#define	IP_DF 0x4000			/* don't fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define IP_FLAG_MASK 0xe000
  u_char	ip_ttl;			/* time to live */
  u_char	ip_p;			/* protocol */
  u_short	ip_sum;			/* checksum */
  struct	in_addr ip_src,ip_dst;	/* source and dest address */
}  __attribute__ ((packed));

#define	IP_MAXPACKET	65535		/* maximum packet size */

/*
 * Definitions for options.
 */
#define	IPOPT_COPIED(o)		((o)&0x80)
#define	IPOPT_CLASS(o)		((o)&0x60)
#define	IPOPT_NUMBER(o)		((o)&0x1f)

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_DEBMEAS		0x40
#define	IPOPT_RESERVED2		0x60

#define	IPOPT_EOL		0		/* end of option list */
#define	IPOPT_NOP		1		/* no operation */

#define	IPOPT_RR		7		/* record packet route */
#define	IPOPT_TS		68		/* timestamp */
#define	IPOPT_SECURITY		130		/* provide s,c,h,tcc */
#define	IPOPT_LSRR		131		/* loose source route */
#define	IPOPT_SATID		136		/* satnet id */
#define	IPOPT_SSRR		137		/* strict source route */

/*
 * Offsets to fields in options other than EOL and NOP.
 */
#define	IPOPT_OPTVAL		0		/* option ID */
#define	IPOPT_OLEN		1		/* option length */
#define IPOPT_OFFSET		2		/* offset within option */
#define	IPOPT_MINOFF		4		/* min value of above */

/*! Prefix structure of an IP option.
 */
struct ip_option_header {
#if BYTE_ORDER == LITTLE_ENDIAN 
  u_char	ip_opt_num:5,		/* option number */
	        ip_opt_cls:2,		/* option class */
          ip_opt_copied:1; /* option copied */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
  u_char	ip_opt_copied:1, /* option copied */
          ip_opt_cls:2,		 /* option class */
          ip_opt_num:5;    /* option number */
#endif
  u_char  rest[0];         /* pointer to the rest of the option */
}  __attribute__ ((packed));

/*
 * Time stamp option structure.
 */
struct	ip_timestamp {
	u_char	ipt_len;		/* size of structure (variable) */
	u_char	ipt_ptr;		/* index of current entry */
#if BYTE_ORDER == LITTLE_ENDIAN 
	u_char	ipt_flg:4,		/* flags, see below */
		      ipt_oflw:4;		/* overflow counter */
#endif
#if BYTE_ORDER == BIG_ENDIAN 
	u_char	ipt_oflw:4,		/* overflow counter */
		      ipt_flg:4;		/* flags, see below */
#endif
	union ipt_timestamp {
		uint32_t	ipt_time[1];
		struct	ipt_ta {
			struct in_addr ipt_addr;
			uint32_t ipt_time;
		} ipt_ta[1];
	} ipt_timestamp;
}  __attribute__ ((packed));

/* ==========End of Berkeley code ========= */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "readpcap.h"

#define IPV4_MIN_HDR_LEN 20

static struct net_field *
get_ipv4_dst_addr(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_src_addr(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_hdr_len(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_ver(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_tos(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_len(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_id(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_offset(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_flag(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_ttl(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_proto(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_csum(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_payload(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_opt_len(const u_char *buf, size_t buf_len, ...);

static struct net_field *
get_ipv4_opt_val(const u_char *buf, size_t buf_len, ...);

static struct net_field_descriptor ipv4_fields[] = {
  {.name = "dst_addr", .is_regex = false, .field_func = get_ipv4_dst_addr},
  {.name = "src_addr", .is_regex = false, .field_func = get_ipv4_src_addr},
  {.name = "hdr_len", .is_regex = false, .field_func = get_ipv4_hdr_len},
  {.name = "ver", .is_regex = false, .field_func = get_ipv4_ver},
  {.name = "tos", .is_regex = false, .field_func = get_ipv4_tos},
  {.name = "len", .is_regex = false, .field_func = get_ipv4_len},
  {.name = "id", .is_regex = false, .field_func = get_ipv4_id},
  {.name = "offset", .is_regex = false, .field_func = get_ipv4_offset},
  {.name = "flag", .is_regex = false, .field_func = get_ipv4_flag},
  {.name = "ttl", .is_regex = false, .field_func = get_ipv4_ttl},
  {.name = "proto", .is_regex = false, .field_func = get_ipv4_proto},
  {.name = "csum", .is_regex = false, .field_func = get_ipv4_csum},
  {.name = "payload", .is_regex = false, .field_func = get_ipv4_payload},
  {.name = "option.len", .is_regex = false, .field_func = get_ipv4_opt_len},
  {.name = "option\\[\\([0-9]\\|[1-9][0-9]*\\)\\].\\(.*\\)", .is_regex = true,
   .field_func = get_ipv4_opt_val},
  {.name = NULL, .field_func = NULL}
};

static int ipv4_proto_init(const u_char *buf, size_t buf_size);
static int ipv4_proto_init_once();

struct protocol_descriptor ipv4_protocol = {
  .name =  "IPv4",
  .fields = ipv4_fields,
  .init = ipv4_proto_init,
  .clean = NULL,
  .upper_proto = NULL,
  .init_once = ipv4_proto_init_once
};

/* ================== IPv4 option parser  ====================*/

static struct ip_option_header *
advance_to_opt_header(const u_char *buf, size_t buf_len, int n);

static int
extract_opt_index(const char *qual_field_name, const regex_t *rcomp);

typedef struct net_field* (*ipv4_opt_parser)(const u_char *buf, size_t buf_size, ...);

struct ipv4_opt_descriptor {
  const char *name;
  bool is_regex;
  regex_t regex;
  ipv4_opt_parser field_func;
};

/*
 * Common IPv4 option parsing functions.
 * Not specific to any particular option.
 */
static struct net_field *
get_ipv4_opt_copied(const u_char *buf, size_t buf_size, ...);

static struct net_field *
get_ipv4_opt_class(const u_char *buf, size_t buf_size, ...);

static struct net_field *
get_ipv4_opt_num(const u_char *buf, size_t buf_size, ...);

static struct net_field *
get_ipv4_opt_len(const u_char *buf, size_t buf_size, ...);

static struct ipv4_opt_descriptor ipv4_opt_common_fields[] = {
  {.name = "copied", .is_regex = false, .field_func = get_ipv4_opt_copied},
  {.name = "class", .is_regex = false, .field_func = get_ipv4_opt_class},
  {.name = "number", .is_regex = false, .field_func = get_ipv4_opt_num},
  {.name = NULL}
};

/*
 * IPv4 timestamp option parsing functions.
 */
static struct net_field *
get_ipv4_ts_opt_len(const u_char *buf, size_t buf_size, ...);

static struct net_field *
get_ipv4_ts_opt_ptr(const u_char *buf, size_t buf_size, ...);

static struct net_field *
get_ipv4_ts_opt_oflw(const u_char *buf, size_t buf_size, ...);

static struct net_field *
get_ipv4_ts_opt_flg(const u_char *buf, size_t buf_size, ...);

static struct net_field *
get_ipv4_ts_opt_addr(const u_char *buf, size_t buf_size, ...);

static struct net_field *
get_ipv4_ts_opt_ts(const u_char *buf, size_t buf_size, ...);

static struct net_field *
get_ipv4_ts_opt_ts_len(const u_char *buf, size_t buf_size, ...);

static struct ipv4_opt_descriptor ipv4_opt_ts_fields[] = {
  {.name = "len", .field_func = get_ipv4_ts_opt_len},
  {.name = "ptr", .field_func = get_ipv4_ts_opt_ptr},
  {.name = "oflw", .field_func = get_ipv4_ts_opt_oflw},
  {.name = "flg", .field_func = get_ipv4_ts_opt_flg},
  {.name = "addr\\[\\([0-9]\\|[1-9][0-9]*\\)\\]", .field_func = get_ipv4_ts_opt_addr, .is_regex = true},
  {.name = "ts\\[\\([0-9]\\|[1-9][0-9]*\\)\\]", .field_func = get_ipv4_ts_opt_ts, .is_regex = true} ,
  {.name = "ts_len", .field_func = get_ipv4_ts_opt_ts_len, .is_regex = false},
  {.name = NULL}
};

/*
 * IPv4 option number to option struct mapping.
 */
static struct ipv4_opt_descriptor*  ipv4_opt_num_mapping[] = {
  NULL,
  NULL,
  NULL,
  NULL,
  ipv4_opt_ts_fields,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
};

static int
ipv4_proto_init_once()
{
  struct net_field_descriptor *desc1;
  struct ipv4_opt_descriptor *desc2;

  /*
   * Initialize the regex for the ipv4 header fields.
   */
  for (desc1 = ipv4_fields; desc1->name != NULL; desc1++) {
    if(desc1->is_regex == true) {
      if (regcomp(&(desc1->regex), desc1->name, 0) != 0) {
        return -1;
      }
    }
  }

  /*
   * Initialize the regex for the ipv4 common option fields.
   */
  for (desc2 = ipv4_opt_common_fields; desc2->name != NULL; desc2++) {
    if (desc2->is_regex == true) {
      if(regcomp(&(desc2->regex), desc2->name, 0) != 0) {
        return -1;
      }
    }
  }

  /*
   * Initialize the regex for the specific ipv4 option fields.
   */
  for (int i = 0; i < sizeof(ipv4_opt_num_mapping) / sizeof(desc2); i++) {
    if (ipv4_opt_num_mapping[i] != NULL) {
      desc2 = ipv4_opt_num_mapping[i];
      for(; desc2->name != NULL; desc2++) {
	if (desc2->is_regex == true) {
	  if (regcomp(&(desc2->regex), desc2->name, 0) != 0) {
	    return -1;
	  }
	}
      }
    }
  }

  return 0;
}

static int
ipv4_proto_init(const u_char *buf, size_t buf_size)
{
  struct ip *header = (struct ip *)buf;
  // Check that the version is 4.
  if (header->ip_v != 4) {
    return -1;
  }

  if (buf_size < IPV4_MIN_HDR_LEN) {
    return -1;
  }

  return (header->ip_hl << 2);
}

/*
 * Check the buffer length is bigger than
 * the IPv4 header length.
 */
#define CHK_BUF_LEN(buf_len) \
  do {\
    if (buf_len < sizeof(struct ip)) {\
      do_fatal("not enough bufferred data, expect at least " \
	       "%d bytes, have %d bytes", \
	       sizeof(struct ip), buf_len); \
    }\
  } while(0)

/*
 * IPv4 address representation length, i.e, the length of
 * "xxx.xxx.xxx.xxx".
 */
#define IPV4_ADDR_REPR_LEN 16

struct net_field *
get_ipv4_dst_addr(const u_char* buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header;
  INIT_NET_FIELD(nf);

  char *dst_addr = (char *)malloc(IPV4_ADDR_REPR_LEN);
  if (dst_addr == NULL)
    do_fatal("can not allocate IPv4 destination address");

  header = (struct ip *)buf;
  if (inet_ntop(AF_INET, &header->ip_dst.s_addr, dst_addr,
		IPV4_ADDR_REPR_LEN) == NULL) {
    free(dst_addr);
    return NULL;
  }

  nf->str_val = dst_addr;
  nf->str_len = strlen(dst_addr) ;
  nf->type = awk_str_t;

  return nf;
}

struct net_field *
get_ipv4_src_addr(const u_char  *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header;
  INIT_NET_FIELD(nf);

  char *src_addr = (char *)malloc(IPV4_ADDR_REPR_LEN);
  if (src_addr == NULL) {
    do_fatal("can not allocate IPv4 source address");
  }

  header = (struct ip *)buf;
  if (inet_ntop(AF_INET, &header->ip_src.s_addr, src_addr,
		IPV4_ADDR_REPR_LEN) == NULL) {
    free(src_addr);
    return NULL;
  }

  nf->str_val = src_addr;
  nf->str_len = strlen(src_addr);
  nf->type = awk_str_t;

  return nf;
}

struct net_field *
get_ipv4_hdr_len(const u_char *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header = (struct ip *)buf;
  INIT_NET_FIELD(nf);

  nf->type = awk_numbr_t;
  nf->num_val = header->ip_hl << 2;

  return nf;
}

struct net_field *
get_ipv4_ver(const u_char *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header = (struct ip *)buf;
  INIT_NET_FIELD(nf);

  nf->type = awk_numbr_t;
  nf->num_val = header->ip_v;

  return nf;
}

struct net_field *
get_ipv4_tos(const u_char *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header = (struct ip *)buf;
  INIT_NET_FIELD(nf);

  nf->type = awk_numbr_t;
  nf->num_val = header->ip_tos;

  return nf;
}

struct net_field *
get_ipv4_len(const u_char *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header = (struct ip *)buf;
  INIT_NET_FIELD(nf);

  nf->type = awk_numbr_t;
  nf->num_val = ntohs(header->ip_len);

  return nf;
}

struct net_field *
get_ipv4_id(const u_char *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header = (struct ip *)buf;
  INIT_NET_FIELD(nf);

  nf->type = awk_numbr_t;
  nf->num_val = ntohs(header->ip_id);

  return nf;
}

struct net_field *
get_ipv4_offset(const u_char *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header = (struct ip *)buf;
  INIT_NET_FIELD(nf);

  nf->type = awk_numbr_t;
  nf->num_val = (u_short)(ntohs(header->ip_off) << 3);

  return nf;
}

struct net_field *
get_ipv4_flag(const u_char *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header = (struct ip *)buf;
  INIT_NET_FIELD(nf);

  nf->type = awk_numbr_t;
  nf->num_val = ntohs(header->ip_off) >> 13;

  return nf;
}

struct net_field *
get_ipv4_ttl(const u_char *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header = (struct ip *)buf;
  INIT_NET_FIELD(nf);

  nf->type = awk_numbr_t;
  nf->num_val = header->ip_ttl;

  return nf;
}

struct net_field *
get_ipv4_proto(const u_char *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header = (struct ip *)buf;
  INIT_NET_FIELD(nf);

  nf->type = awk_numbr_t;
  nf->num_val = header->ip_p;

  return nf;
}

struct net_field *
get_ipv4_csum(const u_char *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  struct ip *header = (struct ip *)buf;
  INIT_NET_FIELD(nf);

  nf->type = awk_numbr_t;
  nf->num_val = ntohs(header->ip_sum);

  return nf;
}

struct net_field *
get_ipv4_payload(const u_char *buf, size_t buf_len, ...)
{
  CHK_BUF_LEN(buf_len);

  /*
   * Check if the buf_len >= IPv4 total length.
   */
  struct net_field *len_field = get_ipv4_len(buf, buf_len);
  int len = (int)len_field->num_val;
  free(len_field);
  if (len > buf_len) {
    do_fatal("not enough buffered data for IPv4 payload, expect %d bytes, "
	     "have %d bytes",len, buf_len);
  }

  struct net_field *hlen_field = get_ipv4_hdr_len(buf, buf_len);
  int hlen = (int)hlen_field->num_val;
  free(hlen_field);

  struct ip *header = (struct ip *)buf;
  INIT_NET_FIELD(nf);

  nf->bin_val = (u_char *)malloc(buf_len - hlen);
  if (nf->bin_val == NULL) {
    do_fatal("can not allocate IPv4 payload");
  }

  nf->type = awk_bin_t;
  memcpy(nf->bin_val, buf + hlen, buf_len - hlen);
  nf->bin_len = buf_len - hlen;

  return nf;
}

static struct ip_option_header *
advance_to_opt_header(const u_char *buf, size_t buf_len, int n)
{
  struct ip_option_header *opt_header = (struct ip_option_header *)(buf +IPV4_MIN_HDR_LEN);
  int hdr_len = ((struct ip *)buf)->ip_hl << 2;

  while ((u_char *)opt_header - buf < hdr_len && --n >= 0) {
    if (opt_header->ip_opt_num == 0) {
      return NULL;
    }
    else if (opt_header->ip_opt_num == 1) {
      opt_header = (struct ip_option_header *)((u_char *)opt_header + 1);
    }
    else if (opt_header->ip_opt_num == 2) {
      opt_header = (struct ip_option_header *)((u_char *)opt_header + 11);
    }
    else if (opt_header->ip_opt_num == 3 || opt_header->ip_opt_num == 4 ||
        opt_header->ip_opt_num == 7 || opt_header->ip_opt_num == 9) {
      u_char opt_len = *((u_char *)opt_header + sizeof(*opt_header));
      opt_header = (struct ip_option_header *)((u_char *)opt_header + opt_len);
    }
    else if (opt_header->ip_opt_num == 8) {
      opt_header = (struct ip_option_header *)((u_char *)opt_header + 4);
    }
    else {
      do_fatal("unknown IPv4 option, option number: %d",
	       opt_header->ip_opt_num);
    }
  }

  if ((const u_char *)opt_header - buf > hdr_len) {
    do_fatal("Not enough buffered data for IPv4 header: expected at least %d bytes, have %d bytes",
	     (const u_char *)opt_header - buf, hdr_len);
    return NULL;
  } else {
    return opt_header;
  }
}

static int
extract_opt_index(const char *qual_field_name, const regex_t *rcomp)
{
  char index[3];
  regmatch_t pm[3];

  if (regexec(rcomp, qual_field_name, 3, pm, 0) !=0) {
    do_fatal("invalid IPv4 option name");
  }

  strncpy(index, qual_field_name + pm[1].rm_so, pm[1].rm_eo - pm[1].rm_so);
  index[pm[1].rm_eo - pm[1].rm_so] = '\0';

  return atoi(index);
}

static const char*
extract_opt_field(const char *qual_field_name, const regex_t *rcomp)
{
  char index[3];
  regmatch_t pm[3];

  if (regexec(rcomp, qual_field_name, 3, pm, 0) != 0) {
    do_fatal("invalid IPv4 option name");
  }

  return qual_field_name + pm[2].rm_so;
}

static struct net_field *
get_ipv4_opt_len(const u_char *buf, size_t buf_len, ...)
{
  int len = 0;
  struct ip_option_header *opt_header
    = (struct ip_option_header *)(buf + IPV4_MIN_HDR_LEN);
  struct ip *header = (struct ip *)buf;
  int hdr_len = header->ip_hl << 2;
  INIT_NET_FIELD(nf);

  while ((u_char *)opt_header - buf < hdr_len) {
    len += 1;
    if (opt_header->ip_opt_num == 0 || opt_header->ip_opt_num == 1) {
      opt_header = (struct ip_option_header *)((u_char *)opt_header + 1);
      if (opt_header->ip_opt_num == 0) {
        break;
      }
    }
    else if (opt_header->ip_opt_num == 2) {
      opt_header = (struct ip_option_header *)((u_char *)opt_header + 11);
    }
    else if (opt_header->ip_opt_num == 3 || opt_header->ip_opt_num == 4 ||
        opt_header->ip_opt_num == 7 || opt_header->ip_opt_num == 9) {
      u_char opt_len = *((u_char *)opt_header + sizeof(*opt_header));
      opt_header = (struct ip_option_header *)((u_char *)opt_header + opt_len);
    }
    else if (opt_header->ip_opt_num == 8) {
      opt_header = (struct ip_option_header *)((u_char *)opt_header + 4);
    }
    else {
      do_fatal("Unknown IPv4 option, option number: %d",
	       opt_header->ip_opt_num);
    }
  }

  if ((const u_char *)opt_header - buf > hdr_len) {
    do_fatal("not enough buffered data for IPv4 header: expected at least %d bytes, have %d bytes",
  	     (const u_char *)opt_header - buf,  hdr_len);
    return NULL;
  }

  nf->type = awk_numbr_t;
  nf->num_val = len;

  return nf;
}

static struct net_field *
get_ipv4_opt_val(const u_char *buf, size_t buf_len, ...)
{
  va_list ap;
  const char *qual_field_name;
  const regex_t *rcomp;
  const struct ip_option_header *opt_header;
  const char *opt_field;
  struct ipv4_opt_descriptor *desc;

  va_start(ap, buf_len);
  qual_field_name = va_arg(ap, const char *);
  rcomp = va_arg(ap, const regex_t *);

  opt_header = advance_to_opt_header(buf, buf_len,
		  extract_opt_index(qual_field_name, rcomp));
  opt_field = extract_opt_field(qual_field_name, rcomp);

  // Check the common option fields
  for (desc = ipv4_opt_common_fields; desc->name != NULL; ++desc) {
    if (!strcmp(desc->name, opt_field)) {
      va_end(ap);
      // Check whether we have enough data.
      if((const u_char*)opt_header - buf  + sizeof(*opt_header) > buf_len) {
        do_fatal("not enough buffered data, expect at least %d bytes, "
                      "have %d bytes",
		      (const u_char*)opt_header - buf  + sizeof(*opt_header),
		      buf_len);
      }
      return desc->field_func((const u_char *)opt_header, sizeof(*opt_header));
    }
  }

  // Get the opt num
  struct net_field *opt_num_field =
      get_ipv4_opt_num((const u_char *)opt_header, sizeof(opt_header));
  int opt_num = (int)(opt_num_field->num_val);
  free(opt_num_field);

  // Check the option specific fields
  desc = ipv4_opt_num_mapping[opt_num];
  if (desc == NULL) {
    va_end(ap);
    do_fatal("unknown IPv4 option, option number: %d", opt_num);
  }
  size_t opt_offset = (const u_char *)opt_header + sizeof(opt_header) - buf;
  for (; desc->name != NULL; ++desc) {
    if (!desc->is_regex && !strcmp(desc->name, opt_field)) {
	va_end(ap);
	size_t opt_offset = (const u_char *)opt_header - buf;
	return desc->field_func((const u_char *)opt_header->rest,
				              buf_len - opt_offset - 1);
    } else if (desc->is_regex && !regexec(&desc->regex, opt_field, 0, NULL, 0)) {
        va_end(ap);
        size_t opt_offset = (const u_char *)opt_header - buf;
        return desc->field_func((const u_char *)opt_header->rest,
				              buf_len - opt_offset - 1, opt_field, &desc->regex);
    }
  }

  va_end(ap);
  do_fatal("unknown option field %s for IPv4 option number %d",
	        opt_field, opt_num);
  return NULL;
}

static struct net_field *
get_ipv4_opt_copied(const u_char *buf, size_t buf_len, ...)
{
  INIT_NET_FIELD(nf);
  struct ip_option_header *opt_header = (struct ip_option_header *)buf;

  nf->type = awk_numbr_t;
  nf->num_val = opt_header->ip_opt_copied;

  return nf;
}

static struct net_field *
get_ipv4_opt_class(const u_char *buf, size_t buf_len, ...)
{
  INIT_NET_FIELD(nf);
  struct ip_option_header *opt_header = (struct ip_option_header *)buf;

  nf->type = awk_numbr_t;
  nf->num_val = opt_header->ip_opt_cls;

  return nf;
}

static struct net_field *
get_ipv4_opt_num(const u_char *buf, size_t buf_len, ...)
{
  INIT_NET_FIELD(nf);
  struct ip_option_header *opt_header = (struct ip_option_header *)buf;

  nf->type = awk_numbr_t;
  nf->num_val = opt_header->ip_opt_num;

  return nf;
}

#define CHK_TS_BUF_LEN(buf, buf_len)\
  do {\
    struct net_field *ts_len;\
    ts_len = get_ipv4_ts_opt_len(buf, buf_len);\
    if (ts_len->num_val - 1 > buf_len) {\
      do_fatal("not enough buffered data for IPv4 timestamp option, expect at least %d bytes, "\
                    "have %d bytes", (int)(ts_len->num_val), buf_len);\
      free(ts_len);\
      return NULL;\
    }\
    free(ts_len);\
  } while(0)

static struct net_field *
get_ipv4_ts_opt_len(const u_char *buf, size_t buf_len, ...)
{
  if (buf_len < 1) {
    do_fatal("not enough buffered data for IPv4 timestamp option: "
	          "expect at least 1 bytes, have 0 bytes");
  }
  INIT_NET_FIELD(nf);
  struct ip_timestamp *opt_header = (struct ip_timestamp *)buf;

  nf->type = awk_numbr_t;
  nf->num_val = opt_header->ipt_len;

  return nf;
}

static struct net_field *
get_ipv4_ts_opt_ptr(const u_char *buf, size_t buf_len, ...)
{
  CHK_TS_BUF_LEN(buf, buf_len);

  INIT_NET_FIELD(nf);
  struct ip_timestamp *opt_header = (struct ip_timestamp *)buf;

  nf->type = awk_numbr_t;
  nf->num_val = opt_header->ipt_ptr;

  return nf;
}

static struct net_field *
get_ipv4_ts_opt_oflw(const u_char *buf, size_t buf_len, ...)
{
  CHK_TS_BUF_LEN(buf, buf_len);

  INIT_NET_FIELD(nf);
  struct ip_timestamp *opt_header = (struct ip_timestamp *)buf;

  nf->type = awk_numbr_t;
  nf->num_val = opt_header->ipt_oflw;

  return nf;
}

static struct net_field *
get_ipv4_ts_opt_flg(const u_char *buf, size_t buf_len, ...)
{
  CHK_TS_BUF_LEN(buf, buf_len);

  INIT_NET_FIELD(nf);
  struct ip_timestamp *opt_header = (struct ip_timestamp *)buf;

  nf->type = awk_numbr_t;
  nf->num_val = opt_header->ipt_flg;

  return nf;
}

static struct net_field *
get_ipv4_ts_opt_addr(const u_char *buf, size_t buf_len, ...)
{
  CHK_TS_BUF_LEN(buf, buf_len);

  // Check whether the IPv4 addresses are available.
  // If the flag field is 0, then no address is available.
  struct net_field *flg_field = get_ipv4_ts_opt_flg(buf, buf_len);
  int flg =flg_field->num_val;
  free(flg_field);
  if (flg == 0) {
    do_fatal("no IPv4 address available. flag=0");
  }

  // Check whether the option index is out of bound.
  // If the flag field is 0, then each timestamp consists of 4 bytes.
  // If the flag field is 1 or 3, then each addr-timestamp pair consits of 8 bytes.
  // We have (opt_index + 1) * (4|8) <= length_field - 4 (including, type, length, pointer, flag and oflw fields)

  // Get the length field
  struct net_field *len_field = get_ipv4_ts_opt_len(buf, buf_len);
  int len = len_field->num_val;
  free(len_field);

  // Get the pointer field
  struct net_field *ptr_field = get_ipv4_ts_opt_ptr(buf, buf_len);
  int ptr = ptr_field->num_val;
  free(ptr_field);

  va_list ap;
  const char *qual_field_name;
  const regex_t *rcomp;

  va_start(ap, buf_len);
  qual_field_name = va_arg(ap, const char *);
  rcomp = va_arg(ap, const regex_t *);

  // Get the option index
  int idx = extract_opt_index(qual_field_name, rcomp);
  if ((idx + 1) * 8 > ((ptr > len) ? len : ptr - 1) - 4) {
    va_end(ap);
    do_fatal("option index out of bound: have %d bytes of timestamps, "
	          "requested timestamp extends to %d bytes",
		  ((ptr > len) ? len : ptr - 1) - 4, (idx + 1) * 8);
  }

  INIT_NET_FIELD(nf);
  struct ip_timestamp *opt_header = (struct ip_timestamp *)buf;

  char *src_addr = (char *)malloc(IPV4_ADDR_REPR_LEN);
  if (src_addr == NULL) {
    va_end(ap);
    do_fatal("can not allocate IPv4 address");
  }

  if (inet_ntop(AF_INET,
		      &opt_header->ipt_timestamp.ipt_ta[idx].ipt_addr.s_addr,
		      src_addr,
		      IPV4_ADDR_REPR_LEN) == NULL) {
    va_end(ap);
    free(src_addr);
    do_fatal("cannot convert the IPv4 address to a string representation");
  }

  va_end(ap);

  nf->str_val = src_addr;
  nf->str_len = strlen(src_addr);
  nf->type = awk_str_t;

  return nf;
}

static struct net_field *
get_ipv4_ts_opt_ts(const u_char *buf, size_t buf_len, ...)
{
  CHK_TS_BUF_LEN(buf, buf_len);

  struct net_field *flg_field = get_ipv4_ts_opt_flg(buf, buf_len);
  int flg =flg_field->num_val;
  free(flg_field);

  // Get the length field
  struct net_field *len_field = get_ipv4_ts_opt_len(buf, buf_len);
  int len = len_field->num_val;
  free(len_field);

  // Get the pointer field
  struct net_field *ptr_field = get_ipv4_ts_opt_ptr(buf, buf_len);
  int ptr = ptr_field->num_val;
  free(ptr_field);

  va_list ap;
  const char *qual_field_name;
  const regex_t *rcomp;

  va_start(ap, buf_len);
  qual_field_name = va_arg(ap, const char *);
  rcomp = va_arg(ap, const regex_t *);

  // Get the option index
  int idx = extract_opt_index(qual_field_name, rcomp);
  if ((idx + 1) * (flg == 0? 4 : 8) > (ptr > len ? len : ptr - 1) - 4) {
      va_end(ap);
      do_fatal("option index out of bound: have %d bytes of timestamps, "
      	          "requested timestamp extends to %d bytes",
      		  ((ptr > len) ? len : ptr - 1) - 4, (idx + 1) *  (flg == 0? 4 : 8));
  }

  va_end(ap);

  INIT_NET_FIELD(nf);
  struct ip_timestamp *opt_header = (struct ip_timestamp *)buf;
  unsigned long ts;

  if (flg == 0) {
    ts = ntohl(opt_header->ipt_timestamp.ipt_time[idx]);
  } else {
    ts = ntohl(opt_header->ipt_timestamp.ipt_ta[idx].ipt_time);
  }

  nf->num_val = ts;
  nf->type = awk_numbr_t;

  return nf;
}

static struct net_field*
get_ipv4_ts_opt_ts_len(const u_char *buf, size_t buf_len, ...)
{
  CHK_TS_BUF_LEN(buf, buf_len);

  struct net_field *flg_field = get_ipv4_ts_opt_flg(buf, buf_len);
  int flg =flg_field->num_val;
  free(flg_field);

  // Get the length field
  struct net_field *len_field = get_ipv4_ts_opt_len(buf, buf_len);
  int len = len_field->num_val;
  free(len_field);

  // Get the pointer field
  struct net_field *ptr_field = get_ipv4_ts_opt_ptr(buf, buf_len);
  int ptr = ptr_field->num_val;
  free(ptr_field);

  INIT_NET_FIELD(nf);
  nf->num_val = ((ptr > len ? len : ptr - 1) - 4) / (flg == 0 ? 4 : 8);
  nf->type = awk_numbr_t;

  return nf;
}

