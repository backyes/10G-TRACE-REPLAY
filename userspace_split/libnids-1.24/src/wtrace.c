#include <stdio.h>
#include "pcap.h"
#include "nids.h"

#define L2_LEN 	nids_linkoffset
char L2[256]={1,2,3,4,5,6,7,8,9,10,\
					11,12,0x08,0x00,15,16,17,18,19,20, \
					21,22,23,24,25,26,27,28,29,30
					};
/*
 * IP packet
 */
int write_ip(FILE *fp,char *ip,unsigned int len,char *hdr) {
	
	/*write the pcap packet hdr*/
	int rlen;	
	if((rlen=fwrite(L2,1,L2_LEN,fp))!=L2_LEN) {
		printf("Cannot write enough data to file,(MAC)\n");
		return 0;
	}
	if((rlen=fwrite(ip,1,len,fp))!=len) {
		printf("Cannot write enough data to file, (IP)\n");
		return 0;
	}
	/* when <60BYTE packet*/
	char trailer[60];
	int caplen=((struct pcap_pkthdr*)hdr)->caplen;
	if((len+L2_LEN)<caplen) {
		if((rlen=fwrite(trailer,1,caplen-len-L2_LEN,fp))!=(caplen-len-L2_LEN)) {
		printf("cannot write enough data to file,(pcap header)\n");
		return 0;
		}
	}
	return 1;
}

int write_pcap_hdr(FILE *fp, char *hdr,unsigned int len) {
	int rlen;
	/*it is a stupid method to cope with the difference between mm hdr and sf hdr*/
	pcap_sf_pkthdr_t sf_pkthdr;
	sf_pkthdr.tv_sec=((struct pcap_pkthdr*)hdr)->ts.tv_sec;
	sf_pkthdr.tv_usec=((struct pcap_pkthdr*)hdr)->ts.tv_usec;
	sf_pkthdr.caplen=((struct pcap_pkthdr*)hdr)->caplen;
	sf_pkthdr.len=((struct pcap_pkthdr*)hdr)->len;
	
	if((rlen=fwrite(&sf_pkthdr,1,len,fp))!=len) {
		printf("cannot write enough data to file,(pcap header)\n");
		return 0;
	}
	return 1;
}
	
