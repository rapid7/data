# nmap scripts

These are two nmap scripts that we developed to find and interrogate Codesys V3
PLCs on a network.

The scripts are currently [waiting in a PR for merging](https://github.com/nmap/nmap/pull/2373)
into the nmap codebase. As soon as they are merged, they will be distributed by
default with nmap.

Until then, you can copy the contents of the `nselib` and `scripts`
subdirectories into the appropriate locations under `/usr/share/nmap` and run
them like this.

Unicast interrogation:

    nmap --script codesys-plc-info -sU -p1740 192.168.20.5

Broadcast search

    nmap --script broadcast-codesys-discover -e enp11s0f0.20
