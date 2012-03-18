#include <stdio.h>

int write_ip(FILE *fp,char *ip,unsigned int len,char*hdr);
int write_pcap_hdr(FILE *fp, char *hdr, unsigned int len); 
