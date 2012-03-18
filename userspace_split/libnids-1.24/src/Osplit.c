
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include "nids.h"


/*pcap file format*/
typedef struct pf_hdr {
	u_int32_t    magic;
	u_int16_t    version_major;
	u_int16_t    tversion_minor;
	int32_t   thiszone;  /* gmt to local correction */
	u_int32_t    sigfigs; /* accuracy of timestamps */
	u_int32_t    snaplen; /* max length saved portion of each pkt */
	u_int32_t    linktype;   /* data link type (LINKTYPE_*) */
} pf_hdr_t;

#define TCPDUMP_MAGIC      0xa1b2c3d4 /*no swap, and tcpdump pcap format*/

pf_hdr_t pf_header;
int 
main (int argc, char *argv[])
{
	int opt;
	char n[10];
	int i=0;
	char tracefile[256];
	while ((opt = getopt(argc, argv, "f:")) != -1) {
		switch (opt) {
			case 'f':
				printf("Split trace: %s.\n", optarg);
				strncpy(tracefile, optarg, 127);
				nids_params.filename=tracefile;
				break;
			case ':':
				printf("option needs a value.\n");
				return 0;
			case '?':
				printf("unknown option: %c\n", opt);
				return 0;
		}

	} /* end while */
	if(nids_params.filename==NULL) {
		printf("please give a trace file name\n");
		return 0;
	}
	char file[SPLIT_FILE_NUM][256];
	FILE *forig=fopen(nids_params.filename,"r");
	if(forig==NULL) {
		printf("error when fopen,(%s)\n",nids_params.filename);
		return 0;
	}
	if(fread(&pf_header,1,sizeof(pf_hdr_t),forig)!=sizeof(pf_hdr_t)) {
		printf("error when fread,(pcap file header)\n");
		return 0;
	}
	pf_header.sigfigs=0;/*in practise, it's always zero*/

	if (!nids_init ())
	{
		fprintf(stderr,"%s\n",nids_errbuf);
		return 0;	
	}
	printf("the generated traces in /home/backyes/trace/split0.pcap split1.pcap ...\n");
	for(i=0;i<SPLIT_FILE_NUM;i++) {
		sprintf(file[i],"/home/backyes/trace/split%d.pcap",i);	
		split_file[i]=fopen(file[i],"w");
		if(split_file[i]==NULL) printf("error when fopen\n");
		/*write the pcap file header*/
		if(fwrite((char*)&pf_header,1,sizeof(pf_hdr_t),split_file[i])!=sizeof(pf_hdr_t))
			printf("error when fwrite,(pcap file header)");

	}
	nids_run();

	printf("%ld packet dropped,total packets:%ld\n",tot_filter_nr,cur_seq);
	for(i=0;i<SPLIT_FILE_NUM;i++) {
		fflush(split_file[i]);
		fclose(split_file[i]);
	}
	return 0;
}

