#include <stdint.h>
#include <pcap.h>
#include <stdlib.h>
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

#include "gawkapi.h"
#include "gettext.h"

#include "readpcap.h"
#include "protocol.h"
#include "hashmap.h"


/*!
 * Define a special protocol called "PKT_PROTO".
 * This protocol contains three pieces of information
 * about the entire packet:
 * 1. Packet length.
 * 2. Captured packet length.
 * 3. Packet timestamp.
 */
static struct net_field *
get_pkt_len(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_pkt_caplen(const u_char *buf, size_t buf_len, ...);
static struct net_field *
get_pkt_ts(const u_char *buf, size_t buf_len, ...);

static struct net_field_descriptor PKT_FIELDS[] = {
  {.name = "ts", .is_regex = false, .field_func = get_pkt_ts},
  {.name = "len", .is_regex = false, .field_func = get_pkt_len},
  {.name = "caplen", .is_regex = false, .field_func = get_pkt_caplen},
  {.name = NULL, .field_func = NULL}
};

static struct protocol_descriptor PKT_PROTO = {
  .name = "PKT",
  .fields = PKT_FIELDS,
  .init = NULL,
  .init_once = NULL,
  .clean = NULL,
  .upper_proto = NULL,
  .header_start = NULL,
  .header_len = 0
};

static const gawk_api_t *api;
static awk_ext_id_t ext_id;
static const char *ext_version = "pcap extension: version 0.0.2";
static awk_bool_t init_readpcap();
static awk_bool_t (*init_func)(void) = init_readpcap;
int plugin_is_GPL_compatible;
#define _(msg) ext_id, msg

//!  do_flags tell whether pcap mode (live or offline) is enabled or not.
extern int do_flags;
//!  pcap mode flags. Has to keep in sync with main.c.
static int  DO_PCAP_LIVE = 0x8000;
static int DO_PCAP_OFFLINE = 0x10000;

void
init_net_field(struct net_field **nf)
{
  *nf = (struct net_field *)malloc(sizeof(NET_FIELD));
  if (NULL == *nf)
    fatal(_("can not allocate network field"));
  (*nf)->str_val = NULL;
  (*nf)->str_len = 0;
  (*nf)->type = awk_str_t;
}

static char ERR_BUF[PCAP_ERRBUF_SIZE];

/*!
 * STACK represents the TCP/IP stack with the Data link layer
 * protocols at the bottom, then network layer protocls,
 * then transport layer protocols, and finally application
 * layer protocols at the top.
 */
static struct protocol_descriptor **STACK[] = {
  DL_LAYER_PROTOS,
  NET_LAYER_PROTOS,
  TRANS_LAYER_PROTOS,
  APP_LAYER_PROTOS
};

/*!
 * Main structure for the pcap extension.
 */
typedef struct pcap_io {
  //! pcap handloe
  pcap_t *handle;
  struct bpf_program fp;

  //! Current packet info and data.
  struct pcap_pkthdr  *pkt_header;
  const u_char        *pkt_data;

  //! Current packet's protocols at each layer.
  struct protocol_descriptor *protos[NUM_LAYERS];

  //! Overall packet stats
  unsigned long long   pkt_num;       // Total number of packet processed
  unsigned long long   good_pkt_num;  // Total number of good packets
  unsigned long long   bad_pkt_num;   // Total number of bad packets

  /*!
   * Whether the current packet is read successfully
   * from the capture. True if yes, or at the
   * end of the capture, false otherwise.
   */
  bool                 pkt_read_ok;
  /*!
   * Hashmap that maps a field name to its correspoding net_field
   * structure if it is already parsed. Avoid parsing the same
   * field name multiple times for the current packet.
   */
  map_t               *field_htab;
  /*!
   * Data link layer type returned by the pcap library.
   * Used to initialized the data link laye protocol
   * for the current packet.
   */
	int                  dlt;
} PCAP_IO;

/*!
 * Given structre pio_io, define shortcut names for
 * the packet length, the packet capture length,
 * and the packet timestamp for the curren packet.
 */
#define pkt_ts     pkt_header->ts
#define pkt_caplen pkt_header->caplen
#define pkt_len    pkt_header->len

/*!
 * Given struct pio_io, define MACROs to get
 * the protocol header pointer, and the
 * protocol header length of a particular
 * network layer for the current packet.
 */
#define PROTO_HEADER_START(layer) protos[(layer)]->header_start
#define PROTO_HEADER_LEN(layer) protos[(layer)]->header_len

/*!
 * Given struct pio_io, define the MACRO to
 * initialize the protocol header, that is
 * the header start pointer, and the header length,
 * at a certain network layer for the current
 * packet.
 *
 * The header start pointer is initialized correctly
 * according to the header start pointer and
 * the header length of the protocol on the lower layer.
 * The header length is initialized to the distance
 * from the start pointer to the end of the packet.
 *
 * It is the responsibility of the protocol init function
 * to initialize the header length to the correct value.
 */
#define INIT_PROTO_HEADER(layer, pio) \
  do { \
    if ((layer) == 0) { \
	    (pio)->PROTO_HEADER_START((layer)) = (pio)->pkt_data;  \
      (pio)->PROTO_HEADER_LEN((layer)) = (pio)->pkt_caplen; \
	  } else { \
      (pio)->PROTO_HEADER_START((layer)) \
        = (pio)->PROTO_HEADER_START((layer) - 1) \
        + (pio)->PROTO_HEADER_LEN((layer) - 1); \
	    const u_char *pkt_end = (pio)->pkt_data + (pio)->pkt_caplen; \
	    (pio)->PROTO_HEADER_LEN((layer)) \
        = pkt_end - (pio)->PROTO_HEADER_START((layer)); \
    } \
  } while(0)

/*!
 * Macro that initializes the struct pcap_io.
 */
#define INIT_PIO(pio) \
  do { \
	  pio->handle = NULL; \
	  pio->pkt_header = NULL; \
	  pio->pkt_data = NULL; \
	  for (int i = 0; i < NUM_LAYERS; i++) \
	    pio->protos[i] = NULL; \
	  pio->pkt_num = 0; \
	  pio->good_pkt_num = 0; \
	  pio->bad_pkt_num = 0; \
	  pio->pkt_read_ok = false; \
	  pio->field_htab = NULL; \
	  pio->dlt = PCAP_ERROR_NOT_ACTIVATED;\
  } while(0)

/*!
 * Define the struct pcap_io instance.
 */
static struct pcap_io PIO;

/*!
 * Initialize the current protocol at a certain network layer.
 *
 * \param layer the network layer index.
 * \param pio the main packet capture structure.
 * \return =0 means the initialization is successful;
 *         =-1 means the initialization is failed
 *         (including the init funciton is NULL).
 */
static int init_proto(int layer, struct pcap_io *pio)
{
  INIT_PROTO_HEADER(layer, pio);
	if (pio->protos[layer]->init != NULL) {
		int header_len = pio->protos[layer]->init(
			pio->PROTO_HEADER_START(layer),
			pio->PROTO_HEADER_LEN(layer)
		);
		if (header_len >= 0) {
		  pio->protos[layer]->header_len = header_len;
			return 0;
		}
	}

  // This protocol does not have an init function,
	// or the init function fails.
	return -1;
}

/*!
 * Represents a split of the network field name of the form
 * proto.field, such as "ipv4.src".
 *
 * proto_name is the protocol name.
 * field_name is the field name.
 */
typedef struct name_split {
  char *proto_name;
  char *field_name;
} NAME_SPLIT;

/*!
 * Macro that free dynamically allocated struct net_field.
 */
#define FREE_FIELD(nf) \
    do { \
	    if ((nf)->type == awk_str_t && (nf)->str_val) \
	      free((nf)->str_val); \
			if ((nf)->type == awk_bin_t && (nf)->bin_val) \
			  free((nf)->bin_val); \
	    free((nf)); \
    } while(0)

/*!
 * Return the timestamp of the curren packet. 
 */
static inline double
pkt_timestamp(const struct pcap_io *pio)
{
  return pio->pkt_ts.tv_sec * (uint64_t)1000 + pio->pkt_ts.tv_usec / 1000.0;
}

/*!
 * Return the split of a full network field name.
 */
static struct name_split
split_field_name(char *qual_field_name)
{
	struct name_split ns = {.proto_name = NULL, .field_name = NULL};
  const char *end = qual_field_name + strlen(qual_field_name);
  const char *dot = strstr(qual_field_name, ".");

	if (NULL == dot) {
	  ns.proto_name = NULL;
	  ns.field_name = strndup(qual_field_name, strlen(qual_field_name));
	  return (ns);
  }

  if (dot == qual_field_name || '\0' == *(dot + 1)) {
	  return (ns);
	}

  ns.proto_name = strndup(qual_field_name, dot - qual_field_name);
  ns.field_name = strndup(dot + 1, end - dot - 1);

  return (ns);
}

/*!
 * Free the struct net_field, and the qual_field_name in the hashmap.
 */
static inline int
free_field(any_t _unused, any_t qual_field_name, any_t nf)
{
  char *real_field_name = (char *)qual_field_name;
  struct net_field *real_nf = (struct net_field *)nf;
  free(real_field_name);
  FREE_FIELD(real_nf);
  return MAP_OK;
}

/** \brief Probe the protocols at a certain network layer.
 *
 *   Try to find a protocol in a network layer that can
 *   parse the current packet.
 *
 *   \param layer network layer.
 *   \param pio struct pcap_io pointer.
 *   \return 0 if the protocol is found and initialized, -1 otherwise.
 */
static int
probe_proto(int layer, struct pcap_io *pio)
{
	struct protocol_descriptor *pd;

  if (layer < 0 || layer >= NUM_LAYERS)
		return (-1);

  // Try to get the protocol from the lower network layer.
	if (layer > 0 && pio->protos[layer - 1]->upper_proto != NULL) {
    const char *proto_name = pio->protos[layer - 1]->upper_proto(
      pio->PROTO_HEADER_START(layer - 1),
			pio->pkt_data + pio->pkt_caplen - pio->PROTO_HEADER_START(layer - 1)
		);
		if (proto_name != NULL) {
			// Find the correct protocol!
			// Try to get the corresponding struct protocol_descriptor.
      pd = get_proto(STACK[layer], proto_name);
			if (pd != NULL) {
				// If the protocol_descriptor is found,
				// assign it as the protocol of this layer and
				// try to initialize it. 
				pio->protos[layer] = pd;
        if (init_proto(layer, pio) < 0) {
					// The initialization fails. Reset
					// the protocol at this network layer
					// and return -1.
					pio->protos[layer] = NULL;
					return -1;
				} else {
					// Everything is fine. Return 0.
					return 0;
				}
			} else {
				// The protocol_descriptor is not found.
				// Cannot parse the packet at this network layer.
        // Reset the protocol at this network layer and
				// return -1.
				pio->protos[layer] = NULL;
				return -1;
			}
		}
	}

	// Determine data link layer protocol.
	if (layer == 0) {
	  pio->protos[DL_LAYER] = get_dl_proto(pio->dlt);
	  if (pio->protos[DL_LAYER] == NULL) {
		  return -1;
	  }
	  if (init_proto(DL_LAYER, pio) < 0) {
		  return -1;
	  }
	  return 0;
  }

  // Probe the correct protocols at network layer "layer".
	int i = 0;
	pd = STACK[layer][i];
  for(; pd; pd = STACK[layer][++i]) {
	  if (pd->init == NULL)
		  continue;
		pio->protos[layer] = pd;
		if(init_proto(layer, pio) < 0) {
			continue;
		} else {
			return 0;
		}
	}
	pio->protos[layer] = NULL;
	return -1;
}

/*! \breif Extract a network filed from the current packet.
*
* Given a full network field name, i.e., proto_name.field_name
  (except the packet level fields with no proto_name)
* extract the corresponding network field from the current packet.
*  
* Firstly it tries to find the correct protocol in the protocol
* stack. During this process, the protocol at each network layer
* is initilialized. If one of the initilization fails, a NULL
* pointer is returned to indicate the error. The NULL pointer is
* also returned, if the protocol specified by the proto_name cannot
* be found in the packet.
*
* Secondly if the correct protocol is found, it tries to extract
* the network field. If the extraction fails or the field_name
* cannot be find in the protocol, a NULL pointer is returned.
*
* Otherwise, the corresponding network field is cached
* in a hashmap for later references, and is returned.
*
* \param qual_field_name a full network field name, i.e.
*        proto_name.field_name or just field_name (packet level).
* \param pio the main structure.
* \return a pointer to the extracted network field or NULL.
*/
struct net_field *
pio_get_field(char *qual_field_name, struct pcap_io *pio)
{
  int i;
  struct net_field_descriptor *nf;
  struct name_split ns;
  struct net_field *res = NULL;

  if (!pio->pkt_read_ok) {
    return (res);
  }

  /* we already parsed this qualified field name. */
  if (MAP_OK == hashmap_get(pio->field_htab, qual_field_name, (void **)&res)) {
    return (res);
  }

  /* we need to parse the packet for the field. */
  ns = split_field_name(qual_field_name);
  if (ns.field_name == NULL && ns.proto_name == NULL) {
    fatal(_("invalid network field name %s"), qual_field_name);
  }

  /* packet level info, use PKT_PROTO */
  if (strcmp(ns.proto_name, "PKT") == 0) {
    /* packet level field */
    GET_NET_FIELD(ns.field_name, nf, &PKT_PROTO);
    if (IS_GUARD_NF(nf)) {
      goto get_field_end;
    }
    res = nf->field_func(PKT_PROTO.header_start, PKT_PROTO.header_len);
    if (res) {
      if (MAP_OMEM == hashmap_put(pio->field_htab, strdup(qual_field_name), res)) {
        fatal(_("can not cache the network field."));
      }
    }
    goto get_field_end;
  }

  /* protocol level info, find the right protocol and field */
  for (i = 0; i < NUM_LAYERS; i++) {
    if (pio->protos[i] == NULL) {
      // Probe the right protocol at this network layer.
      if (probe_proto(i, pio) < 0) {
        // Probe failed.
        goto get_field_end;
      }
    }
    if (strcmp(ns.proto_name, pio->protos[i]->name) != 0) {
      // Not the protocol we wanted.
      continue;
    }
    GET_NET_FIELD(ns.field_name, nf, pio->protos[i]);
    if (IS_GUARD_NF(nf)) {
      goto get_field_end;
    }
    if (nf->is_regex) {
      res = nf->field_func(pio->protos[i]->header_start,
		                       pio->pkt_caplen - (pio->protos[i]->header_start - pio->pkt_data),
				       ns.field_name, &(nf->regex));
    } else {
      res = nf->field_func(pio->protos[i]->header_start,
	                               pio->pkt_caplen - (pio->protos[i]->header_start - pio->pkt_data));
    }
    if (res) {
      if (MAP_OMEM == hashmap_put(pio->field_htab, strdup(qual_field_name), res)) {
        fatal(_("can not cache the network field."));
      }
    }
    goto get_field_end;
  }

get_field_end:
  if (ns.proto_name) free(ns.proto_name);
  if (ns.field_name) free(ns.field_name);
  if (res == NULL) {
    fatal(_("invalid network field name"));
  }
  return (res);
}

/*! \brief Preparatoin work after getting the next packet.
*
* Prepration work done after getting the next packet, including
* (1) Clean the network stack: call the clean function of the
*     protocol at each network layer.
* (2) Reset the protocol at each network layer to NULL.
* (3) Clean the hashmap for the network field.
* (4) Initialize the packet level protocol.
* (5) Initialize the data link layer protocol.
* If it cannot find the data link layer protocol, or
* the initialization fails, it returns -1, otherwise
* return 0.
* \param pio the main structure.
* \return 0 on success or -1 on failure.
*/
static int
pio_next_pkt(struct pcap_io *pio)
{
	int i;

  /*
	 * clean pio->protos.
	 */
  for(i = 0; i < NUM_LAYERS; i++) {
	  if (pio->protos[i] == NULL) {
			continue;
		}
		/* call protocol-specific clean func */
	  if (NULL != pio->protos[i]->clean) {
	    pio->protos[i]->clean();
		}
		pio->protos[i] = NULL;
  }

  /* clean the network field cache */
  hashmap_iterate(pio->field_htab, free_field, NULL);
  hashmap_free(pio->field_htab);
  pio->field_htab = hashmap_new();
  if (!pio->field_htab) {
	  fatal(_("can not create network field cache"));
		return -1;
	}

  /* init PKT_PROTO */
	PKT_PROTO.header_start = pio->pkt_data;
	PKT_PROTO.header_len = pio->pkt_caplen;
}

/*! \brief Initialize the main structure, and the
*          hashmap cache for the network fields.
*  \param fname the packet capture file name.
*  \param pio the main structure.
*  \return 0 on success, -1 otherwise.
*/
static int
pio_init(const char *fname, struct pcap_io *pio)
{
	int dlt;
	const char *dlt_name;

	/* Initialize the PIO */
	INIT_PIO(pio);

	if (( pio->handle = pcap_open_offline(fname, ERR_BUF)) == NULL)
		fatal(_("can not open the capture file %s(%s)"), fname, ERR_BUF);

  dlt = pcap_datalink(pio->handle);
	dlt_name = pcap_datalink_val_to_name(dlt);
	if (dlt_name == NULL) {
		fprintf(stderr, "reading from file %s, link-type %u\n", fname, dlt);
		return -1;
  } else {
		fprintf(stderr,
	          "reading from file %s, link-type %s (%s)\n",
	          fname, dlt_name,
	          pcap_datalink_val_to_description(dlt));
  }

  /* record the dlt in PIO */
	pio->dlt = dlt;

  /* initialize the network field cache */
  pio->field_htab = hashmap_new();
  if (!pio->field_htab) {
	  fatal(_("can not create network field cache"));
	}

	return 0;
}

/*! \brief Get the next packet.
 *  
 * This function get the next packet from the capture
 * and fill the packet data buffer. If the next packet
 * is successfully read into the buffer, call pio_next_pkt
 * to intialize it.
 * 
 * If all are successful, return 0.
 * If pio_next_pkt failed, return -1.
 * If packet read error, return -2.
 * If no more packet, return -3.
 * 
 * \param pio the main structure.
 * \return 0 on success, -1, -2, -3 on failure. 
 */
static int
pcap_get_next(struct pcap_io *pio)
{
  int flag;

  flag = pcap_next_ex(pio->handle, &(pio->pkt_header), &(pio->pkt_data));

  if (flag == 1) {
	  pio->pkt_num++;
    pio->good_pkt_num++;
	  pio->pkt_read_ok = true;
		if (pio_next_pkt(pio) != 0) {
		  return -1;
		} else {
	    return 0;
		}
  } else if (flag == 0) {
	  ; /* Only meaningful when doing live capture. */
  } else if (flag == PCAP_ERROR) {
	  fprintf(stderr, "Error reading the packet: %s", pcap_geterr(pio->handle));
    pio->pkt_num++;
	  pio->bad_pkt_num++;
	  pio->pkt_read_ok = false;
	  return -2;
  } else if (flag == PCAP_ERROR_BREAK) {
	  pio->pkt_read_ok = true;
	  return -3;
  }

  return 0;
}

void
do_fatal(const char *format, ...)
{
  va_list args;

  va_start(args, format);
  fatal_v(_(format), args);
  va_end(args);
}

static struct net_field*
get_pkt_len(const u_char *buf, size_t buf_len, ...)
{
  INIT_NET_FIELD(nf);
  nf->num_val = (AWKNUM)PIO.pkt_len;
  nf->type = awk_numbr_t;

  return (nf);
}

static struct net_field *
get_pkt_caplen(const u_char *buf, size_t buf_len, ...)
{
  INIT_NET_FIELD(nf);
  nf->num_val = (AWKNUM)PIO.pkt_caplen;
  nf->type = awk_numbr_t;

  return (nf);
}

static struct net_field *
get_pkt_ts(const u_char *buf, size_t buf_len, ...)
{
  INIT_NET_FIELD(nf);
  nf->num_val = (AWKNUM)pkt_timestamp(&PIO);
  nf->type = awk_numbr_t;

  return (nf);
}

static int
readpcap_get_record(char **out, awk_input_buf_t *iobuf, int *errcode,
    char **rt_start, size_t *rt_len)
{
  if (out == NULL || iobuf == NULL)
	  return EOF;

  int res = pcap_get_next(&PIO);
	if (res == -1 && res == -2) {
		*errcode = EBADF;
		return EOF;
	} else if (res == -3) {
		return EOF;
	}

  *out = (char *)PIO.pkt_data;
  *rt_start = (char *)PIO.pkt_data;
  *rt_len = PIO.pkt_caplen;

  return PIO.pkt_caplen;
}

int
readpcap_get_field(struct awk_input *iobuf, int *errcode,
	           char *field_name, char **fl_start, size_t *fl_len)
{
	struct net_field *nf;

	nf = pio_get_field(field_name, &PIO);
	if (!nf) {
		*errcode = 1;
		return -1;
	}

  if (nf->type == awk_str_t || nf->type == awk_bin_t) {
	  *fl_start = nf->str_val;
    *fl_len = (size_t)nf->str_len;
	} else {
		*fl_start = (char *)&nf->num_val;
		*fl_len = sizeof(AWKNUM);
	}

	return nf->type;
}

static awk_bool_t
readpcap_can_take_file(const awk_input_buf_t *iobuf)
{
  awk_value_t array, index, value;

  if (NULL == iobuf)
	  return awk_false;

	if ((do_flags | DO_PCAP_LIVE) || (do_flags | DO_PCAP_OFFLINE)) {
	  return awk_true;
	}

	return awk_false;
}

static awk_bool_t
readpcap_take_control_of(awk_input_buf_t *iobuf)
{
  if (iobuf == NULL)
    return awk_false;

  pio_init(iobuf->name, &PIO);
  iobuf->get_record = readpcap_get_record;
  iobuf->get_field = readpcap_get_field;
  return awk_true;
}

static awk_input_parser_t readpcap_parser = {
  "readpcap",
  readpcap_can_take_file,
  readpcap_take_control_of,
  NULL
};

static awk_bool_t
init_readpcap()
{
	// Run the init_once for every supported protocol.
  for (int layer = 0; layer < 4; layer++) {
		for (int n = 0; STACK[layer][n]; n++) {
			if (STACK[layer][n]->init_once != NULL) {
				if (STACK[layer][n]->init_once() < 0) {
					return awk_false;
				}
			}
		}
	}

  register_input_parser(&readpcap_parser);
  return awk_true;
}


/* Include all builtin function definition headers below.
 * A builtin function definition header defines the builtin
 * functions as static, e.g.
 *
 * xxx_def.h:
 * static awk_value_t my_builtin(int nargs, awk_value_t *result)
 * {
 * ...
 * }
 *
 * Along with each builtin function definition header, there should
 * be another header xxx.h of the form,
 *
 * xxx.h:
 * {"func_name", my_builtin, 1},
 * ... 
 *
 * Include this header in the func_table array.
 */
#include "pcap_builtin_def.h"

static awk_ext_func_t func_table[] = {
#include <pcap_builtin.h>
};

dl_load_func(func_table, readpcap, "")
