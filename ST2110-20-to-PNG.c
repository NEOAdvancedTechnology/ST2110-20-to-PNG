// ========================================================
// SMPTE ST 2110-20 pcap file to PNG generator
//
// This program will search in a pcap file for the first
// full frame of video (based on RTP marker bits) and
// will generate a PNG file of that frame.
//
// The file must contain ONLY packets of the desired
// ST 2110-20 flow.
//
// Author: Thomas Edwards, thomas.edwards@fox.com
// FOX Networks Engineering & Operations
//
// ========================================================
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// ========================================================
//
// This program depends on "lodepng", please obtain this from:
// http://lodev.org/lodepng/
// https://github.com/lvandeve/lodepng
//
// Also libpcap:
// http://www.tcpdump.org
// https://github.com/the-tcpdump-group/libpcap
//
//
// compile with:
// $ cc ST2110-20-to-PNG.c lodepng.c -o ST2110-20-to-PNG -lpcap
//
// This software has been tested on:
//  OS X El Capitan 10.11.6
//
// ========================================================

#define DEBUG 0 // set to 1 to get a lot of debug printfs

#include "lodepng.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <string.h>

char *outFileName=NULL;
char *inFileName=NULL;

int collectingData = 0; // are we skipping over packets or assembling the image
int x=0; // global image x values
int y=0; // global image y values
int Xres=1280; // default values
int Yres=720; // default values
int interlaced=0;
int MCount=1; // number of marker bits to process, 1 for progressive, 2 for interlaced

unsigned char* image;

//
// please define based on your architecture.
// RTP_LITTLE_ENDIAN seems to work for OS X El Capitan
//
#define RTP_LITTLE_ENDIAN 1
struct rtp_hdr {
#if RTP_BIG_ENDIAN
    unsigned int version:2;   /* protocol version */
    unsigned int p:1;         /* padding flag */
    unsigned int x:1;         /* header extension flag */
    unsigned int cc:4;        /* CSRC count */
    unsigned int m:1;         /* marker bit */
    unsigned int pt:7;        /* payload type */
#elif RTP_LITTLE_ENDIAN
    unsigned int cc:4;        /* CSRC count */
    unsigned int x:1;         /* header extension flag */
    unsigned int p:1;         /* padding flag */
    unsigned int version:2;   /* protocol version */
    unsigned int pt:7;        /* payload type */
    unsigned int m:1;         /* marker bit */
#else
#error Define one of RTP_LITTLE_ENDIAN or RTP_BIG_ENDIAN
#endif
    
    unsigned int seq:16;      /* sequence number */
    u_int32_t ts;               /* timestamp */
    u_int32_t ssrc;             /* synchronization source */
};

// clamp floats to 0-255 and return value as unsigned char
unsigned char clamp(float value){
    unsigned char out=(value < 0 ? 0 : (value > 255 ? 255 : value));
    return(out);
}

// retrieve sample from SR Data Segment, channel=0 for chroma, 1 for luma
unsigned short s(u_char *SRDSegment,int sample,int channel)
{
    int bitsIn=0;
    if(channel==0){
        bitsIn=sample*20;
    }
    else{
        bitsIn=10+(sample*20);
    }
    
    unsigned short output=0;
    int pv=9; /* place value */
    
    for(int bits=bitsIn;bits<bitsIn+10;++bits){
        output+=((SRDSegment[bits/8] & (128 >> (bits%8)))!=0)<<(pv--);
    }
    return(output);
}


void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    const struct udphdr* udpHeader;
    const struct rtp_hdr* rtpHeader;
    
    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    u_int sourcePort, destPort;
    int udpDataLength = 0;
    int rtpDataLength = 0;
    u_char *data;
    int field = 0;
// RTP Packets shall not contain more than three Sample Row Data Headers
    int SRDLength[3] = {0,0,0};
    int SRDRowNumber[3] = {0,0,0};
    int SRDOffset[3] = {0,0,0};
    
    int continuation = 0;
    int pOffset = 0; // offset into RTP payload, starting at end of extended sequence number
    

    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
    }
    
    if (ipHeader->ip_p == IPPROTO_UDP) {
        udpHeader = (const struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        sourcePort = ntohs(udpHeader->uh_sport);
        destPort = ntohs(udpHeader->uh_dport);
        udpDataLength = ntohs(udpHeader->uh_ulen)-sizeof(struct udphdr);
        
        rtpHeader=(const struct rtp_hdr *)(packet + sizeof(struct ether_header) +sizeof(struct ip) + sizeof(struct udphdr));
        
        if(rtpHeader->x){
            printf("RTP Header Extension present - cannot process header extensions properly - exiting\n");
            exit(EXIT_FAILURE);
        }
        
        data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)
                         +sizeof(struct rtp_hdr));

        if(collectingData){
            
            rtpDataLength=udpDataLength-sizeof(struct rtp_hdr);
            int extendedSN=data[1] | data[0] << 8;
#if DEBUG
            printf("----------------------------------------\n");
            printf("destIP: %s\n",destIp);
            printf("sport=%d dport=%d udpDataLength=%d\n",sourcePort,destPort,udpDataLength);
            printf("RTP data length = %d\n",rtpDataLength);

            printf("version: %d\n",rtpHeader->version);
            printf("marker: %d\n",rtpHeader->m);
            printf("payload type: %d\n",rtpHeader->pt);
            printf("sequence number: %d\n",ntohs(rtpHeader->seq));
            printf("timestamp: %u\n",ntohl(rtpHeader->ts));
            printf("extended SN: %d\n",extendedSN);
#endif
            
            continuation=1; // to get while loop going
            pOffset=2; // start after extended sequence number
            
            // process SRD Headers
            int SRDHeaderNumber=0;
            while(continuation==1) {
               
                SRDLength[SRDHeaderNumber]=data[pOffset+1] | data [pOffset] << 8;
                SRDRowNumber[SRDHeaderNumber] = data[pOffset+3] | (data[pOffset+2] & 0b01111111) << 8;
                field = (data[pOffset+2] & 0x80)==0 ? 0 : 1;

                SRDOffset[SRDHeaderNumber] = data[pOffset+5] | (data[pOffset+4] & 0b01111111) << 8;
                continuation = (data[pOffset+4] & 0x80)==0 ? 0 : 1;

                pOffset+=6;
                SRDHeaderNumber++;
#if DEBUG
                printf("Field: %d\n",field);
                printf("Continuation: %d\n",continuation);
#endif
            }
            
            // process SR Data Segments
            for(int i=0;i<SRDHeaderNumber;++i){

                // convert from octets to samples, assume 10-bit samples
                int numberPixels = (SRDLength[i] << 3)/20;
#if DEBUG
                printf("SRDLength: %d\n",SRDLength[i]);
                printf("SRDRowNumber: %d\n",SRDRowNumber[i]);
                printf("SRD Offset: %d\n",SRDOffset[i]);
                printf("numberPixels = %d\n",numberPixels);
#endif
                
                unsigned short Cb=0;
                unsigned short Cr=0;
        
                x=SRDOffset[i];
                
                // extract pixels from SR Data Segments and place in image
                for(int pixel=0;pixel<numberPixels;pixel++){
#if DEBUG
                    printf("I'm about to s(data[%d],%d,1)\n",pOffset,pixel);
#endif
                    unsigned short Y=s(data+pOffset,pixel,1);
                    if(pixel % 2 ==0){
                        Cb=s(data+pOffset,pixel,0);
                        Cr=s(data+pOffset,pixel+1,0);
                    }
                    
// note: The following YCbCr to RGB conversion seems to look OK
// I'm not representing that it is perfect
                    
                    float R=(1.164*(Y-64)+1.793*(Cr-512));
                    float G=(1.164*(Y-64)-0.534*(Cr-512)-0.213*(Cb-512));
                    float B=(1.164*(Y-64)+2.115*(Cb-512));

                    int Row=SRDRowNumber[i];
                    if(interlaced==1){
                        if(MCount==2){
                            Row=Row<<1;
                        }else if(MCount==1){
                            Row=(Row<<1)+1;
                        }
                    }
                    
                    image[4 * Xres * Row + 4 * x + 0]=clamp((int)(R/4.0));
                    image[4 * Xres * Row + 4 * x + 1]=clamp((int)(G/4.0));
                    image[4 * Xres * Row + 4 * x + 2]=clamp((int)(B/4.0));
                    image[4 * Xres * Row + 4 * x + 3]=255;
                    
#if DEBUG
                    printf("Image x=%d, y=%d: R=%d, G=%d, B=%d\n",x,Row,
                           clamp((int)(R/4.0)),
                           clamp((int)(G/4.0)),
                           clamp((int)(B/4.0)));
#endif
                    
                    x=x+1;
                    
                }
                
                pOffset+=SRDLength[i];
                
            }
            
            if(rtpHeader->m){
                MCount--;
#if DEBUG
                printf("MCount: %d\n",MCount);
#endif
            }
            
            if(MCount==0){
                unsigned error = lodepng_encode32_file(outFileName, image, Xres, Yres);
                /*if there's an error, display it*/
                if(error){
                    printf("error %u: %s\n", error, lodepng_error_text(error));
                    exit(EXIT_FAILURE);
                }
                printf("Wrote %s\n",outFileName);
                exit(EXIT_SUCCESS); // end of frame
            }
        }
        if(rtpHeader->m){
            collectingData=1; // start of frame next packet
        }
        
    }
}

void print_usage(){
    printf("Usage: ST2110-20-to-PNG [-r <720p|1080i>] -i <input pcap file> -o <output png file>\n");
    printf("-r is the active video resolution.  720p is 1280x720 progressive, 1080i is 1920x1080 interlaced.  Resolution is assumed to be 720p if not specified.\n");
}

int main(int argc, char **argv)
{
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    extern char *optarg;
 
    int c;
    while ((c = getopt (argc, argv, "r:i:o:")) != -1)
        switch (c)
    {
        case 'r':
            if(strcmp(optarg,"720p")==0){
                Xres=1280;
                Yres=720;
                interlaced=0;
                MCount=1;
            }
            if(strcmp(optarg,"1080i")==0){
                Xres=1920;
                Yres=1080;
                interlaced=1;
                MCount=2;
            }
        case 'i':
            inFileName = optarg;
            break;
        case 'o':
            outFileName = optarg;
            break;
        default: print_usage();
            exit(EXIT_FAILURE);
    }
    
    if((inFileName==NULL) || (outFileName==NULL)){
        print_usage();
        exit(EXIT_FAILURE);
    }
    
    // open capture file for offline processing
    descr = pcap_open_offline(inFileName, errbuf);
    if (descr == NULL) {
        printf("pcap_open_live() failed: %s\n:",errbuf);
        return 1;
    }else{
         printf("Opening up PCAP file %s\n",inFileName);
    }
    
    image = malloc(Xres * Yres * 4 *sizeof(unsigned char));
    
    // start packet processing loop, just like live capture
    if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
        printf("pcap_loop() failed: %s\n",pcap_geterr(descr));
        return 1;
    }
    
    printf("conversion finished\n");
    
    return 0;

}
