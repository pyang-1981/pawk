#ifndef PCAP_DEF_H
#define PCAP_DEF_H

#include <regex.h>
#include <stddef.h>

typedef enum {
  false = 0,
  true
} bool;

/*!
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

/*!
 * Structure for a network field.
 */
typedef struct net_field {
  union {
    // Field value if it is a string/binary
    struct {
      u_char *val;
      size_t len;
    } s_val;

    /*
     * Field value if it is a number or the size
		 * of the field if it is a string/binary.
     */
    AWKNUM n_val;
  } val;
  NET_FIELD_T type; // What's the type of this field?
} NET_FIELD;

/*!
 * Shortcut names for the members in struct net_field.
 */
#define str_val val.s_val.val
#define bin_val val.s_val.val
#define num_val val.n_val
#define str_len val.s_val.len
#define bin_len val.s_val.len

/*!
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
  char *name;
  //! Whether the name is a regular expression.
  bool is_regex;
  //! Precompiled regex buffer. Only valid when regx == true.
  regex_t regex;
	//! Network field extraction function.
	/*!
   \param buf a pointer to the start of the data buffer.
   \param buf_size the data buffer size.
   \param qual_field_name the qualified network field name without protocol part.
   \return a net_field structure containing the extracted network field.
  */
  struct net_field* (*field_func)(
    const u_char *buf,
    size_t buf_size,
    ...
  );
} NET_FIELD_DESC;


//! Descriptor of a network protocol.
/*!
  A network protocol descriptor describes

 */
typedef struct protocol_descriptor
{
  //! Protocol name.
  char                         *name;
  //! An array of network field descriptors.
  struct net_field_descriptor  *fields;

        /* Before describe the following data members,
         * one needs to understand how PAWK works.
         * PAWK processes each packet in turn in a packet
         * capture. For each packet, it needs to determine
         * the protocol used for each network layer.
         *
         * PAWK assumes that at the lowest layer, a MAC (Media Access Control)
         * or link layer protocol (such as the Ethernet protocol) is used.
         * The specific protocol type can be obtained by pcap library fuction,
         * such as pcap_datalink() from the packet capture itself.
         *
         * The upper layer protocol types can not be directly
         * returned by any pcap library function. PAWK determines
         * them by using a combination of mechanisms.
         *
         * Firstly, many upper layer protocol types are embeded
         * in the corresponding lower layer protocol headers.
         * For example, the Ethernet header has a field called
         * "ethertype" which determines the upper layer protocol type.
         * If this is the case, the upper layer protocol is determined
         * by this mechanism.
         *
         * If a upper layer protocol type is not embeded in the
         * lower layer protocol header, but some heuristic can
         * be used by the lower layer protocol to determine
         * the upper layer protocol type, it is used.
         *
         * For the above two cases, the member fuction upper_proto
         * (see below) is provided to return an identification of
         * the upper layer protocol type. The protcol author should
         * define this fuction appropriately, or assign it to NULL,
         *  if it is impossible to determine the upper layer protocol
         * type.
         *
         * Finally, if PAWK cannot get the upper layer protocol type
         * from upper_proto, it will try the init functions (see below)
         * from all the registered protocols in the upper layer.
         * Whenever a init fuction returns successfully, that protocol
         * is used for the upper layer.
         *
         * If none of the above mechanism works, a protocol unknown
         * error is raised. Depend on users' choices, PAWK either
         * aborts, or continues to process the next packet with a warning
         * printed.
         */

        //! Protocol init function.
        /*! The protocol init function is called for a certain
             protocol for every packet processed. It should
             initialize pointer head_start to point to the start
             of the protocol header, and initialize
             header_len to the protocol header length.
        \param buf points to the start of a buffer. It is determined
                by the start of the lower layer protocol header
                plus the header length. For the MAC/link layer
                protocols, it points to start of the packet buffer.
        \param buf_size the buffer size. It spans from the
               param buf to the end of the packet buffer.
        \return the header length for success, -1 for failure.
         */
  int (*init)(const u_char *buf, size_t buf_size);

  //! Another initialization function for the protocol.
  /*! Unlie the previous init function which runs before
   *  parsing every packet. This function runs only once
   *  before any parsing.
   */
  int (*init_once)();

  //! Protocol clean func
  /*! The clean func is called when PAWK is ready
   *   to process the next packet.
   */
  void (*clean)();

  //! Upper layer protocol detection func
  /*! The protocol author should provide this function if
   * the upper layer protocol type is embeded in the
   * protocol header or there is some heuristic to infer
   * the upper layer protocol type.
   *
   * \param buf pointer to protocol header start.
   * \param buf_size size from the protocol header
   *         start to the end of the packet buffer.
   * \return the upper layer protocol name;
             or NULL if the upper layer protocol can
             not be identified.
   */
  const char* (*upper_proto)(const u_char *buf, size_t buf_size);

  //! Pointer to the protocol header start.
  const u_char             *header_start;
  //! Protocol header length.
  size_t                   header_len;
} PROTO_DESC;

#define GET_NET_FIELD(fn, nf, pd) \
  do { \
    for(nf = (pd)->fields; (nf)->name; (nf)++) { \
      if (!(nf)->is_regex && 0 == strcmp((nf)->name, (fn))) { \
        break; \
      } \
      if ((nf)->is_regex) { \
        int match = regexec(&(nf)->regex, (fn), 0, NULL, 0); \
        if (!match) { \
          break; \
        } \
      } \
    } \
  } while(0)

#define GET_NET_PROTO(pn, pd) \
  do { \
    for (; (pd)->name; (pd)++) \
      if (0 == strncmp((pd)->name, pn, strlen(pn))) \
        break; \
  } while (0)

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
void do_fatal(const char *format, ...);


#endif //PCAP_DEF_H
