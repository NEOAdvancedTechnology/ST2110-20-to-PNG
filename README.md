# ST2110-20-to-PNG
Converts SMPTE ST 2110-20 PCAP file to PNG image file.

This program will search in a pcap file for the first
full frame of video (based on RTP marker bits) and
will generate a PNG file of that frame.

The file must contain ONLY packets of the desired
ST 2110-20 flow.

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
