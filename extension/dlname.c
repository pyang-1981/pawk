#include <pcap.h>
#include <string.h>

struct dlt_choice {
    const char *name;
    const char *description;
    int dlt;
};

#define DLT_CHOICE(code, description) {#code, description, code}
#define DLT_CHOICE_SENTINEL {NULL, NULL, 0}

static struct dlt_choice dlt_choices[] = {
    DLT_CHOICE(DLT_NULL, "BSD loopback"),
    DLT_CHOICE(DLT_EN10MB, "Ethernet"),
    DLT_CHOICE(DLT_IEEE802, "Token ring"),
    DLT_CHOICE(DLT_ARCNET, "ARCNET"),
    DLT_CHOICE_SENTINEL
};

#ifndef HAVE_PCAP_DATALINK_NAME_TO_VAL
int pcap_datalink_name_to_val(const char *name)
{
    int i;
    
    for (i = 0; dlt_choices[i].name != NULL; i++) {
	if (strcasecmp(dlt_choices[i].name + sizeof("DLT_") - 1,
	    name) == 0)
	    return (dlt_choices[i].dlt);
    }
    return (-1);
}
#endif

const char *
pcap_datalink_val_to_name(int dlt)
{
    int i;
    
    for (i = 0; dlt_choices[i].name != NULL; i++) {
	if(dlt_choices[i].dlt == dlt)
	    return (dlt_choices[i].name + sizeof("DLT_") - 1);
    }
    return (NULL);
}

const char *
pcap_datalink_val_to_description(int dlt)
{
    int i;
    
    for (i = 0; dlt_choices[i].name != NULL; i++) {
	if (dlt_choices[i].dlt == dlt)
	    return (dlt_choices[i].description);
    }
    return (NULL);
}


