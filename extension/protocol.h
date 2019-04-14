#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <pcap.h>
#include <ether.h>
#include <ip.h>

/*
 * Data link layer protocols.
 */
static struct protocol_descriptor* DL_LAYER_PROTOS[] = {
	&ether_protocol,
	NULL,
};

struct dlt_proto {
	int dlt;
	struct protocol_descriptor *proto;
};

static struct dlt_proto dlt_2_proto[] = {
	{DLT_EN10MB, &ether_protocol},
	{-1, NULL}    /* must be the last one. */
};

#define GET_DL_PROTO(dlt_expect, pd) \
        do { \
		for (int i = 0; -1 != dlt_2_proto[i].dlt; i++) { \
			if (dlt_expect == dlt_2_proto[i].dlt) { \
				pd = dlt_2_proto[i].proto; \
				break; \
			} \
		} \
		if (-1 == dlt_2_proto[i].dlt) \
			pd = NULL;  \
	} while(0)

/*
 * Network layer protocols.
 */
static struct protocol_descriptor* NET_LAYER_PROTOS[] = {
        &ipv4_protocol,
	NULL,
};

/*
 * Transport layer protocols.
 */
static struct protocol_descriptor* TRANS_LAYER_PROTOS[] = {
	NULL,
};


/*
 * Application layer protocols. 
 */
static struct protocol_descriptor* APP_LAYER_PROTOS[] ={
	NULL,
};


/*
 * Two special protocols: not_implemented, not_determined. 
 * not_implemented means a specific protocol is not implemented.
 * not_determined means the protocol can not be determined.
 */
struct protocol_descriptor *not_implemented, *not_determined;




#endif // PROTOCOL_H
