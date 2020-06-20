
#include <math.h>
#include <gawkapi.h>

static awk_value_t*
pcap_total_pkt_num(int nargs, awk_value_t *result)
{
  assert(result != NULL);
    
  if (do_lint && nargs != 0)
    lintwarn(ext_id, "total_pkt_num: called with too many arguments");
    
  unset_ERRNO();
  make_number(PIO.pkt_num, result);
    
  return result;
}

static awk_value_t*
pcap_binary_length(int nargs, awk_value_t *result)
{
  awk_value_t bin_data;

  assert(result != NULL);

  if (do_lint && nargs != 1) {
    lintwarn(ext_id, "binary_length: called with wrong number of arguments");
  }

  unset_ERRNO();

  if (get_argument(0, AWK_STRING, &bin_data)) {
    make_number(bin_data.str_value.len, result);
    return result;
	}

  fatal(_("binary_length: cannot get the binary data"));
  return NULL;
}

static awk_value_t*
pcap_binary_at(int nargs, awk_value_t *result)
{
  awk_value_t bin_data;
  awk_value_t index;

  assert(result != NULL);

  if (do_lint && nargs != 2) {
    lintwarn(ext_id, "binary_at: called with wrong number of arguments");
  }

  unset_ERRNO();

  if(get_argument(0, AWK_STRING, &bin_data)) {
    if (get_argument(1, AWK_NUMBER, &index)) {
      if (floor(index.num_value) != index.num_value) {
        fatal(_("binary_at: index is not an integer"));
      }
      if (index.num_value >= bin_data.str_value.len) {
        fatal(_("binary_at: index is out-of-bound"));
      }
      make_number((u_char)(bin_data.str_value.str[(int)(index.num_value)]), result);
      return result;
    }
  }

  fatal(_("binary_at: cannot get the arguments"));
  return NULL;
}

static awk_value_t*
pcap_eval_net_field(int nargs, awk_value_t *result)
{
  awk_value_t field_name;
  struct net_field *nf;

  assert(result != NULL);

  if (do_lint && nargs != 2) {
    lintwarn(ext_id, "binary_at: called with wrong number of arguments");
  }

  unset_ERRNO();

  if (get_argument(0, AWK_STRING, &field_name)) {
    nf = pio_get_field(field_name.str_value.str, &PIO);
    if (!nf) {
	fatal(_("Cannot eval net field %s"), field_name.str_value);
    }
    if (nf->type == awk_str_t || nf->type == awk_bin_t) {
      make_malloced_string(nf->str_val, nf->str_len, result);
    } else {
      make_number(nf->num_val, result);
    }
    return result;
  }
  fatal(_("eval_net_field: cannot get the arguments"));
  return NULL;
}

