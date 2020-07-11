# PAWK Commandline Options
Being an extension of GNU AWK, PAWK has all the commandline options of GNU AWK, with a few extra of its own.

## -lreadpcap
This option loads the shared library *readpcap* which has nearly all the functionalities provided by PAWK.

## -a Or its Longer Version --pcap
This option specifies the mode of the operation. There are two arguments: offline/live. In *offline* mode, one analyzes an existing packet capture file, and in *live* mode, one do online analysis of a on-going packet capture. Currently only *offline* mode is supported. Note that -a(--pcap) without any argument implies *offline* mode.

## Example
```bash
pawk -lreadpcap -a -f [script] [pcap]
```
*script* is the path to the analysis code, and *pcap* is the path to the packet capture file.
