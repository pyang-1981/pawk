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
#include "gawkapi.h"
#include "gettext.h"

#include "readpcap.h"
#include "protocol.h"
#include "hashmap.h"

static struct net_field *
get_pkt_len(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_pkt_caplen(const u_char *buf, size_t buf_len, void *ctx);
static struct net_field *
get_pkt_ts(const u_char *buf, size_t buf_len, void *ctx);

static struct net_field_descriptor PKT_FIELDS[] = {
	{.name= "ts", .field_func = get_pkt_ts},
	{.name = "len", .field_func = get_pkt_len},
	{.name = "caplen", .field_func = get_pkt_caplen},
};


static struct protocol_descriptor PKT_PROTO = {
	.name = "packet",
	.fields = PKT_FIELDS,
};

static const gawk_api_t *api;
static awk_ext_id_t ext_id;
static const char *ext_version = "pcap extension: version 0.1";
static awk_bool_t init_readpcap();
static awk_bool_t (*init_func)(void) = init_readpcap;
int plugin_is_GPL_compatible;
#define _(msg) ext_id, msg

//  do_flags tell whether pcap mode (live or offline) is enabled or not.
extern int do_flags;
//  pcap mode flags. Has to keep in sync with main.c.
static int  DO_PCAP_LIVE = 0x8000;
static int DO_PCAP_OFFLINE = 0x10000;

void
init_net_field(struct net_field **nf)
{
	*nf = (struct net_field *)malloc(sizeof(NET_FIELD));
	if (NULL == *nf)
	       fatal(_("can not allocate network field"));
	(*nf)->str_val = NULL;
}

typedef enum {
    false = 0,
    true
} bool;

static char ERR_BUF[PCAP_ERRBUF_SIZE];

static struct protocol_descriptor **STACK[] = {
    DL_LAYER_PROTOS,
    NET_LAYER_PROTOS,
    TRANS_LAYER_PROTOS,
    APP_LAYER_PROTOS
};

typedef struct pcap_io {
        pcap_t *handle;
        struct bpf_program fp;
 
        /* Current packet info and data */
        struct pcap_pkthdr  *pkt_header;
        const u_char        *pkt_data;
    
        /* Network layer info */
        struct protocol_descriptor *protos[NUM_LAYERS];
    
        /* Stats */
        unsigned long long   pkt_num;       // Total number of packet processed
        unsigned long long   good_pkt_num;  // Total number of good packets
        unsigned long long   bad_pkt_num;   // Total number of bad packets
    
        bool                 pkt_read_ok;
        map_t               *field_htab;
	int                  dlt;
} PCAP_IO;

#define pkt_ts     pkt_header->ts
#define pkt_caplen pkt_header->caplen
#define pkt_len    pkt_header->len
#define PROTO_HEADER_START(layer, pio) ((struct protocol_descriptor *)pio->protos[layer])->header_start
#define PROTO_HEADER_LEN(layer, pio) ((struct protocol_descriptor *)pio->protos[layer])->header_len;
#define INIT_PROTO_HEADER(layer, pd, pio) \
    do { \
	if (layer == 0) { \
	    (pd)->header_start = pio->pkt_data; \
	    (pd)->header_len = pio->pkt_caplen; \
	} else { \
	    (pd)->header_start = PROTO_HEADER_START(layer-1, pio) + PROTO_HEADER_LEN(layer-1, pio); \
	    const u_char *pkt_end = pio->pkt_data + pio->pkt_caplen; \
	    (pd)->header_len = pkt_end - (pd)->header_start; \
	} \
    } while(0)
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

    
static struct pcap_io PIO;


/*
 * Packet parsing context.
 */
typedef struct pkt_ctx
{
	void *ctx;              /* user-provide context, 
	                           must be the first member. */
        struct pcap_io *pio;
	int      init_status;
} PKT_CTX;

#define PROTO_INIT_PENDING 0
#define PROTO_INIT_OK 1
#define PROTO_INIT_FAIL 2
#define REPLACE_CTX(inner, pio) \
	do { \
		struct pkt_ctx *ctx; \
		ctx = (struct pkt_ctx *)malloc(sizeof(*ctx)); \
		if (!ctx) \
			fatal(_("can not allocate the protocol packet context")); \
		ctx->ctx = inner; \
		ctx->pio = pio; \
		ctx->init_status = PROTO_INIT_PENDING; \
		inner = ctx; \
	} while(0)
#define RESTORE_CTX(outer) \
        do { \
		void *tmp = outer; \
	        outer = ((struct pkt_ctx *)(outer))->ctx; \
		free(tmp); \
	} while(0)
#define CTX_PIO(ctx)              ((struct pcap_io *)((char *)(ctx) + offsetof(PKT_CTX, pio)))
#define CTX_PKT_DATA(ctx)         (CTX_PIO(ctx)->pkt_data)
#define CTX_PKT_LEN(ctx)          (CTX_PIO(ctx)->pkt_len)
#define CTX_PKT_CAPLEN(ctx)       (CTX_PIO(ctx)->pkt_caplen)
#define CTX_DL_DESCRIPTOR(ctx)    (CTX_PIO(ctx)->protos[DL_LAYER])
#define CTX_NET_DESCRIPTOR(ctx)   (CTX_PIO(ctx)->protos[NET_LAYER])
#define CTX_TRANS_DESCRIPTOR(ctx) (CTX_PIO(ctx)->protos[TRANS_LAYER])
#define CTX_APP_DESCRIPTOR(ctx)   (CTX_PIO(ctx)->protos[APP_LAYER])
#define CTX_INIT_STATUS(ctx)      *((int *)((char *)(ctx) + offsetof(PKT_CTX, init_status)))

#define INIT_PROTO(layer, pd, pio) \
        do { \
		INIT_PROTO_HEADER(layer, pd, pio); \
		REPLACE_CTX((pd)->ctx, pio); \
		if (NULL != (pd)->init) { \
		        (pd)->init(&((pd)->header_start), &((pd)->header_len), (pd)->ctx); \
		        if (NULL == (pd)->header_start) \
				CTX_INIT_STATUS((pd)->ctx) = PROTO_INIT_FAIL; \
			else \
				CTX_INIT_STATUS((pd)->ctx) = PROTO_INIT_OK; \
		} else { \
			CTX_INIT_STATUS((pd)->ctx) = PROTO_INIT_OK; \
		} \
	} while(0)
#define RESTORE_PROTO(pd) RESTORE_CTX((pd)->ctx)

const u_char* ctx_pkt_data(void* ctx)
{
        return CTX_PKT_DATA(ctx);
}

size_t ctx_pkt_len(void* ctx)
{
        return CTX_PKT_LEN(ctx);
}

size_t ctx_pkt_caplen(void* ctx)
{
        return CTX_PKT_CAPLEN(ctx);
}

struct protocol_descriptor *
ctx_protocol_descriptor(void* ctx, int layer)
{
        if (layer < 0 && layer >= NUM_LAYERS)
	        return NULL;
    
        switch(layer)
        {
	        case DL_LAYER:
		        return CTX_DL_DESCRIPTOR(ctx);
	        case NET_LAYER:
		        return CTX_NET_DESCRIPTOR(ctx);
	        case TRANS_LAYER:
		        return CTX_TRANS_DESCRIPTOR(ctx);
	        case APP_LAYER:
		        return CTX_APP_DESCRIPTOR(ctx);
        }
        
        return (NULL);
}


typedef struct name_split {
        char *proto_name;
        char *field_name;
} NAME_SPLIT;

#define FREE_FIELD(nf) \
    do { \
	    if ((nf)->type == awk_str_t && (nf)->str_val) \
	            free((nf)->str_val); \
	    free(nf); \
    } while(0)
    
#define IS_INVALID_NF(nf) NULL==(nf)->str_val

static inline double
pkt_timestamp(const struct pcap_io *pio)
{ 
    return pio->pkt_ts.tv_sec * (uint64_t)1000 + pio->pkt_ts.tv_usec / 1000.0;
}

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
    
        if (dot == qual_field_name || '\0' == *(dot + 1))
	        return (ns);
    
        ns.proto_name = strndup(qual_field_name, dot - qual_field_name);
        ns.field_name = strndup(dot + 1, end - dot - 1);
    
        return (ns);
}

static inline int
free_field(any_t _unused, any_t nf)
{
        struct net_field *real_nf = (struct net_field *)nf;
        FREE_FIELD(real_nf);
        return MAP_OK;
}

/** \brief Probe the protocols at a certain network layer.
 * 
 *   Try to find a protocol in a network layer that can
 *   parse the current packet.
 * 
 *   \param layer network layer.
 *   \param pio pcap_io pointer.
 *   \return 0 if find a protocol at the specified layer, -1 otherwise.
 */
static int
probe_proto(int layer, struct pcap_io *pio)
{
	struct protocol_descriptor *pd;
    
        if (layer < 0 || layer >= NUM_LAYERS)
		return (-1);
	
	pd = *(STACK[layer]); 
	for(; !pd->name; pd++) {
		if (NULL == pd->init)
			continue;
		INIT_PROTO(layer, pd, pio);
		if (PROTO_INIT_OK == CTX_INIT_STATUS(pd->ctx)) {
			pio->protos[layer] = pd;
			return (0);
		} else {
			RESTORE_PROTO(pd);
		}
	}
	pio->protos[layer] = NULL;
        return (-1);
}

struct net_field *
pio_get_field(char *qual_field_name, struct pcap_io *pio)
{
	int i;
        struct net_field_descriptor *nf;
        struct name_split ns;
        struct net_field *res = NULL;
    
        if (!pio->pkt_read_ok)
	        return (res);
    
        /* we already parsed this qualified field name. */
        if (MAP_OK == hashmap_get(pio->field_htab, (char *)qual_field_name, (void **)&res))
	        return (res);
    
        /* we need to parse the packet for the field. */
        ns = split_field_name(qual_field_name);
        if (NULL == ns.field_name && NULL == ns.proto_name)
		fatal(_("invalid network field name %s"), qual_field_name);
	
	/* packet level info, use PKT_PROTO */
	if (NULL == ns.proto_name) {
		/* packet level field */
		GET_NET_FIELD(ns.field_name, nf, &PKT_PROTO);
	        if (IS_GUARD_NF(nf))
			goto get_field_end;
		res = nf->field_func(PKT_PROTO.header_start, PKT_PROTO.header_len, NULL);
		if (res) {
			if (MAP_OMEM == hashmap_put(pio->field_htab, (char *)qual_field_name, res))
				fatal(_("can not cache the network field."));
		}
		goto get_field_end;
	}
	
	/* protocol level info, find the right protocol and field */
	for (i = 0; i < NUM_LAYERS; i++) {
		if (NULL == pio->protos[i])
			if (probe_proto(i, pio) < 0)
				goto get_field_end;
		if (strncmp(ns.proto_name, pio->protos[i]->name, strlen(ns.proto_name)) != 0)
			continue;
		if (PROTO_INIT_PENDING == CTX_INIT_STATUS(pio->protos[i]->ctx)) {
			RESTORE_CTX(pio->protos[i]->ctx);
			INIT_PROTO(i, pio->protos[i], pio);
			if (PROTO_INIT_FAIL == CTX_INIT_STATUS(pio->protos[i]->ctx))
				goto get_field_end;
		} else if (PROTO_INIT_FAIL == CTX_INIT_STATUS(pio->protos[i]->ctx))
			goto get_field_end;	
		GET_NET_FIELD(ns.field_name, nf, pio->protos[i]);
		if (IS_GUARD_NF(nf))
			goto get_field_end;
		res = nf->field_func(pio->protos[i]->header_start, pio->protos[i]->header_len, pio->protos[i]->ctx);
		if (res) {
			if (MAP_OMEM == hashmap_put(pio->field_htab, (char *)qual_field_name, res))
				fatal(_("can not cache the network field."));
		}
		goto get_field_end;
	}
    
get_field_end:
        if (ns.proto_name) free(ns.proto_name);
        if (ns.field_name) free(ns.field_name);
        return (res);
}

static void 
pio_next_pkt(struct pcap_io *pio)
{
	int i;
    
        /*
	 * clean pio->protos.
	 */
        for(i = 0; i < NUM_LAYERS; i++) {
	        if (NULL == pio->protos[i])
			continue;
		if (PROTO_INIT_PENDING == CTX_INIT_STATUS(pio->protos[i]->ctx) || 
		    PROTO_INIT_FAIL == CTX_INIT_STATUS(pio->protos[i]->ctx)) {
			RESTORE_CTX(pio->protos[i]->ctx);
		} else {
		        /* call protocol-specific clean func */
	                if (NULL != pio->protos[i]->clean)
			        /* we pass the user provided ctx here */
	                        pio->protos[i]->clean(((struct pkt_ctx *)pio->protos[i]->ctx)->ctx);
		        RESTORE_CTX(pio->protos[i]->ctx);
		}
		pio->protos[i] = NULL;
        }
    
        /* clean the network field cache */
        hashmap_iterate(pio->field_htab, free_field, NULL);
        hashmap_free(pio->field_htab);
        pio->field_htab = hashmap_new();
        if (!pio->field_htab)
	    fatal(_("can not create network field cache"));
    
        /* init PKT_PROTO */
	PKT_PROTO.header_start = pio->pkt_data;
	PKT_PROTO.header_len = pio->pkt_caplen;
	
	/* init the DL layer protocol */
	GET_DL_PROTO(pio->dlt, pio->protos[DL_LAYER]);
	if (NULL != pio->protos[DL_LAYER])
		INIT_PROTO(DL_LAYER, pio->protos[DL_LAYER], pio);
}

static void
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
	if (NULL == dlt_name) {
		fprintf(stderr, "reading from file %s, link-type %u\n", fname, dlt);
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
        if (!pio->field_htab)
	        fatal(_("can not create network field cache"));
}

/**
 *  Get the next packet. Return false if no more.
 * */
static bool
pcap_get_next(struct pcap_io *pio)
{
        int flag;
    
        flag = pcap_next_ex(pio->handle, &(pio->pkt_header), &(pio->pkt_data));
        pio_next_pkt(pio);
    
        if (flag == 1) {
	        pio->pkt_num++;
	        pio->good_pkt_num++;
	        pio->pkt_read_ok = true;
	        return (true);
        } else if (flag == 0) {
	        ; /* Only meaningful when doing live capture. */
        } else if (flag == -1) {
	        fprintf(stderr, "Error reading the packet: %s", pcap_geterr(pio->handle));
                pio->pkt_num++;
	        pio->bad_pkt_num++;
	        pio->pkt_read_ok = false;
	        return (false);
        } else if (flag == -2) {
	        pio->pkt_read_ok = true;
	        return (false);
        }
    
        return (false);
}

void
do_fatal(const char *format, ...)
{
	va_list args;
	
	va_start(args, format);
	fatal(_(format), args);
	va_end(args);
}

static struct net_field*
get_pkt_len(const u_char *buf, size_t buf_len, void *ctx)
{
	INIT_NET_FIELD(nf);
	nf->num_val = (AWKNUM)PIO.pkt_len;
	nf->type = awk_numbr_t;
	
	return (nf);
}

static struct net_field *
get_pkt_caplen(const u_char *buf, size_t buf_len, void *ctx)
{
	INIT_NET_FIELD(nf);
	nf->num_val = (AWKNUM)PIO.pkt_caplen;
	nf->type = awk_numbr_t;
	
	return (nf);
}

static struct net_field *
get_pkt_ts(const u_char *buf, size_t buf_len, void *ctx)
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
    
        if(!pcap_get_next(&PIO)) {
	        if (PIO.pkt_read_ok) {
	                return (EOF);
	        } else {
	                *errcode = 1;
	                return (0);
	        }
        }
    
        *out = (char *)PIO.pkt_data;
        *rt_start = (char *)PIO.pkt_data;
        *rt_len = PIO.pkt_caplen;
    
        return (PIO.pkt_caplen);
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
	
	return (nf->type);
}

static awk_bool_t
readpcap_can_take_file(const awk_input_buf_t *iobuf)
{
        awk_value_t array, index, value;
    
        if (NULL == iobuf)
	        return (awk_false);

	if ((do_flags | DO_PCAP_LIVE) || (do_flags | DO_PCAP_OFFLINE)) {
	        return (awk_true);
	}

	return (awk_false);
}

static awk_bool_t
readpcap_take_control_of(awk_input_buf_t *iobuf)
{
        if (iobuf == NULL)
	    return (awk_false);
    
        pio_init(iobuf->name, &PIO);
        iobuf->get_record = readpcap_get_record;
        iobuf->get_field = readpcap_get_field;
        return (awk_true);
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
        register_input_parser(&readpcap_parser);
        return (awk_true);
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
