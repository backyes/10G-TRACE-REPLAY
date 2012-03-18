/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@icm.edu.pl>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_IP_FRAGMENT_H
#define _NIDS_IP_FRAGMENT_H
#include "pcap.h"
#include "nids.h"

#define IPF_NOTF 1
#define IPF_NEW  2
#define IPF_ISF  3


void ip_frag_init(int);
void ip_frag_exit(void);
int ip_defrag_stub(struct ip *, struct ip **);
#ifdef OSPLIT
/* Describe an IP fragment. */
struct ipfrag {
  int offset;			/* offset of fragment in IP datagram    */
  int end;			/* last byte of data in datagram        */
  int len;			/* length of this fragment              */
  struct sk_buff *skb;		/* complete received fragment           */
  unsigned char *ptr;		/* pointer into real fragment data      */
  struct ipfrag *next;		/* linked list pointers                 */
  struct ipfrag *prev;
 #ifdef OSPLIT
  int wtrace_len;/*used to indicate the bytes length of that need to write to trace*/
  struct pcap_pkthdr pcap_header; 
 #endif
};
struct sk_buff {
  char *data;
  int truesize;
};

#ifdef _IP_FRAGMENT_C
#define extern
#endif
extern unsigned int is_frag; /*if the ip packet is a fragment ??*/
extern struct ipfrag *this_fragments;	/* linked list of received fragments */
extern struct ipfrag *this_frag_tail;

#endif

#endif /* _NIDS_IP_FRAGMENT_H */
