# Build and Installation
## Prerequisites
### Autotools
I wish we can do without autotools, since it should be only needed by the maintainer. However, GitHub and autotools do not coexist in harmony, which results in the normal build workflow, i.e., *./configure && make*, not working. Once you install the autotools from your OS distribution, you need to run *autoreconf -fvi* first in the source directory, then proceed with *./configure && make*. Later on, I will provide release source tarballs which have correct timestamps for relevant files and can be built without autotools.

### LIBPCAP
You should install LIBPCAP from your OS distribution. The dev-version is needed, since it has development header files.

## Build
From the source directory, do
```bash
autoreconf -fvi
./configure
make
```

Before installation, check the pawk by running some simple pcap analysis scripts. Do the following from the source directory.
```bash
make run_pcap_analysis
```

## Installation
If everything is fine, install the pawk by running
```bash
sudo make install
```
