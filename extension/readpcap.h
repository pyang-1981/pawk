#ifndef PCAP_DEF_H
#define PCAP_DEF_H

#include <stddef.h>

#define MAX_NAME_LEN 40

/*
 * Define the type of a network field.
 * Currently, a field can be a string,
 * a blob of binary, or a number.
 */
typedef unsigned char u_char;
typedef double AWKNUM;
typedef enum {
	awk_str_t = 0,
	awk_numbr_t,
	awk_bin_t
} NET_FIELD_T;

/*
 * Define the value of a network field.
 */
typedef struct net_field {
	struct {
		// Field value if it is a string/binary. 
		char  *s_val;
                /* Field value if it is a number or the size
		 * of the field if it is a string/binary.
                 */
		AWKNUM n_val;
	} val;
        NET_FIELD_T type; // What's the type of this field?
} NET_FIELD;

/*
 * Shortcut names for the members in struct net_field.
 */
#define str_val val.s_val
#define bin_val val.s_val
#define num_val val.n_val
#define str_len val.n_val
#define bin_len val.n_val

/*
 *  Initialize a network field
 */
extern void init_net_field(struct net_field **nf);
#define INIT_NET_FIELD(nf) \
        struct net_field *nf = NULL; \
        do {			 \
	    init_net_field(&nf); \
        } while(0)


//! Descriptor of a network field.
/*!
  A network field descriptor describes a network field name and
  how to extract it from a data buffer containing
  the data of a protocol. The start of the data buffer aligns with
  the start of the protocol.
 */ 
typedef struct net_field_descriptor
{
	//! The name of the network field.
        char name[MAX_NAME_LEN];
	//! Network field extraction function.
	/*!
         \param buf a pointer to the start of the data buffer.
         \param buf_size the data buffer size.
         \param ctx a pointer to the protocol auxiliary data. 
         */
        struct net_field* (*field_func)(const u_char *buf, size_t buf_size, void *ctx);
} NET_FIELD_DESC;


//! Descriptor of a network protocol.
/*!
  A network protocol descriptor describes 

 */
typedef struct protocol_descriptor
{
    char                         name[MAX_NAME_LEN];
    struct net_field_descriptor  *fields;
    void                         *ctx;
    
    // Protocol init func
    void (*init)(const u_char **buf, unsigned int *buf_size, void *ctx);
    // Protocol clean func
    void (*clean)(void *ctx);
    
    // Protocol buffer
    const u_char             *header_start;
    unsigned int              header_len;
} PROTO_DESC;

#define GET_NET_FIELD(fn, nf, pd) \
        do { \
	    for(nf = (pd)->fields; (nf)->name; (nf)++) { \
	        if (0 == strncmp((nf)->name, fn, strlen(fn))) { \
		    break; \
		} \
	    } \
	} while(0)
	
#define GET_NET_PROTO(pn, pd) \
        do { \
	    for (; (pd)->name; (pd)++) { \
		if (0 == strncmp((pd)->name, pn, strlen(pn))) \
		    break; \
	    } \
	while (0)
	
#define IS_GUARD_NF(nf) (NULL == (nf)->name) 
#define IS_GUARD_PD(pd) (NULL == (pd)->name)

#define NUM_LAYERS 4
#define DL_LAYER 0
#define NET_LAYER 1
#define TRANS_LAYER 2
#define APP_LAYER 3
		
		
/*
 * Fatal 
 */
extern void do_fatal(const char *format, ...);


/*
 *  Context utilities.
 */

/*
 * Get the pointer to the packet data.
 */
extern const u_char *ctx_pkt_data(void *ctx);

/*
 * Get the packet lenght.
 */
extern size_t ctx_pkt_len(void *ctx);

/*
 * Get the packet capature length.
 */
extern size_t ctx_pkt_caplen(void *ctx);

/*
 * Get the protocol descriptor at a certian layer.
 */
extern struct protocol_descriptor *ctx_protocol_descriptor(void *ctx, int layer);



#endif //PCAP_DEF_H
