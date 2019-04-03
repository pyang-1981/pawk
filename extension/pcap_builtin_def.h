
#include <gawkapi.h>

static awk_value_t*
pcap_total_pkt_num(int nargs, awk_value_t *result)
{
        assert(result != NULL);
    
        if (do_lint && nargs != 0)
	        lintwarn(ext_id, "total_pkt_num: called with too many arguments");
    
        unset_ERRNO();
        make_number(PIO.pkt_num, result);
    
        return (result);
}