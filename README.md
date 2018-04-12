# ST2110-20-to-PNG
Converts SMPTE ST 2110-20 PCAP file to PNG image file.

This program will search in a pcap file for the first
full frame of video (based on RTP marker bits) and
will generate a PNG file of that frame.

The file must contain ONLY packets of the desired
ST 2110-20 flow.

**Dependencies**

This program depends on "lodepng", please obtain this from:

http://lodev.org/lodepng/

https://github.com/lvandeve/lodepng


Also libpcap:

http://www.tcpdump.org

https://github.com/the-tcpdump-group/libpcap

**Build Instructions**

Install libpcap.  Have `lodepng.h` and `lodepng.c` in the compile directory.  Note that you need to rename
`lodepng.cpp` to `lodepng.c`

Then compile with:

`$ cc ST2110-20-to-PNG.c lodepng.c -o ST2110-20-to-PNG -lpcap`

This software has been tested on:

  OS X El Capitan 10.11.6

 **Usage**
 
 `ST2110-20-to-PNG [-r <720p|1080i>] -i <input pcap file> -o <output png file>`
 
 `-r` is the active video resolution.  720p is 1280x720 progressive, 1080i is 1920x1080 interlaced.  Resolution is assumed to be "720p" if not specified.
 
 **Files**
 
 ST2110-20-to-PNG.c: Source code
 
 ST_2110_20_color_bars.pcap: ST 2110-20 PCAP capture of a few frames of 720p59.94
 
 ST_2110_20_color_bars.png: Example PNG image output
