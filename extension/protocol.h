#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <pcap.h>
#include <ether.h>
#include <ip.h>
#include <tcp.h>

/*!
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

static struct protocol_descriptor*
get_dl_proto(int dlt)
{
	int i = 0;
	for (i = 0; dlt_2_proto[i].dlt != -1; i++) {
		if (dlt == dlt_2_proto[i].dlt) {
			return dlt_2_proto[i].proto;
		}
	}
	return NULL;
}

/*! 
 * Get the struct protocol_descriptor pointer given a protocol
 * name at a certain network layer.
 * 
 * \param layer an array fo protocol descriptor pointers at a certain network layer.
 * \param proto_name pointer to the protocol name string.
 * \return a struct protocol_descriptor pointer corresponding to
 *         the proto_name at a certain layer, or NULL if search fails. 
 */
static struct protocol_descriptor*
get_proto(struct protocol_descriptor **layer, const char *proto_name)
{
  struct protocol_descriptor *pd;
  int i = 0;
  for (pd = layer[i]; pd != NULL; pd = layer[++i]) {
    if (strcmp(pd->name, proto_name) == 0) {
      return pd;
    }
  }

  return NULL;
}

/*!
 * Network layer protocols.
 */
static struct protocol_descriptor* NET_LAYER_PROTOS[] = {
  &ipv4_protocol,
  NULL,
};

/*!
 * Transport layer protocols.
 */
static struct protocol_descriptor* TRANS_LAYER_PROTOS[] = {
  &tcp_protocol,
  NULL,
};


/*!
 * Application layer protocols. 
 */
static struct protocol_descriptor* APP_LAYER_PROTOS[] ={
  NULL,
};


/*!
 * Two special protocols: not_implemented, not_determined. 
 * not_implemented means a specific protocol is not implemented.
 * not_determined means the protocol can not be determined.
 */
struct protocol_descriptor *not_implemented, *not_determined;


#endif // PROTOCOL_H
