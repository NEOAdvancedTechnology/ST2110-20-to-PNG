# ST2110-20-to-PNG
Converts SMPTE ST 2110-20 PCAP files to PNG image file

This program depends on "lodepng", please obtain this from:
http://lodev.org/lodepng/
https://github.com/lvandeve/lodepng

Also libpcap:
http://www.tcpdump.org
https://github.com/the-tcpdump-group/libpcap

compile with:
`$ cc ST2110-20-to-PNG.c lodepng.c -o ST2110-20-to-PNG -lpcap`

This software has been tested on:
  OS X El Capitan 10.11.6
