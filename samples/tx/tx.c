#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define __USE_GNU

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

#include <sys/wait.h>
#include <sys/time.h>
#include "pkt_buff.h"
#include <pthread.h>
#include <numa.h>

#include "../../include/ps.h"

//! Modified by backyes@gmai.com, Fri Mar 16 18:34:00 CST 2012
//
#define MAX_CPUS 32

int num_devices;
struct ps_device devices[MAX_DEVICES];
int num_devices_attached;
int devices_attached[MAX_DEVICES];
double tot_gbps[MAX_CPUS];
long tot_packets[MAX_CPUS];
double tot_mpps[MAX_CPUS];
int loop = 0;

pthread_barrier_t  barrier;

typedef struct _thread_ctrl {
	pthread_t th_ctrl;
	pthread_barrier_t *barrier;
	struct timeval starttime;
	struct timeval endtime;
	int cpu_id;
	int num_devices_attached;
	int devices_attached[MAX_DEVICES];
	struct ps_handle handle;

}thread_ctrl;

thread_ctrl th_ctrl[MAX_CPUS];
pthread_barrier_t barrier;

int get_num_cpus()
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

int bind_cpu(int cpu)
{
   cpu_set_t *cmask;
	struct bitmask *bmask;
	size_t n;
	int ret;

	n = get_num_cpus();

	if (cpu < 0 || cpu >= (int)n) {
		errno = -EINVAL;
		return -1;
	}
	cmask = CPU_ALLOC(n);
	if (cmask == NULL)
		return -1;

	CPU_ZERO_S(n, cmask);
	CPU_SET_S(cpu, n, cmask);

	ret = sched_setaffinity(0, n, cmask);
	usleep(1000);
	/* skip NUMA stuff for UMA systems */
	if (numa_max_node() == 0)
		return ret;

	bmask = numa_bitmask_alloc(16);
	assert(bmask);

	numa_bitmask_setbit(bmask, cpu % 2);
	numa_set_membind(bmask);
	numa_bitmask_free(bmask);

	return ret;
}

void print_usage(char *argv0)
{
	fprintf(stderr, "Usage: %s <interface to echo> <...>",
			argv0);

	exit(2);
}

void parse_opt(int argc, char **argv)
{
	int i, j;
	int next;

	if (argc < 2)
		print_usage(argv[0]);
	
	if(!strcmp(argv[1], "loop")) {
		loop = 1;
		next = 2;
	}
	else next = 1;

	for (i = next; i < argc; i++) {
		int ifindex = -1;

		for (j = 0; j < num_devices; j++) {
			if (strcmp(argv[i], devices[j].name) != 0)
				continue;

			ifindex = devices[j].ifindex;
			break;
		}

		if (ifindex == -1) {
			fprintf(stderr, "Interface %s does not exist!\n", argv[i]);
			exit(4);
		}

		for (j = 0; j < num_devices_attached; j++) {
			if (devices_attached[j] == ifindex)
				goto already_attached;
		}

		devices_attached[num_devices_attached] = ifindex;
		num_devices_attached++;

already_attached:
		;
	}

	assert(num_devices_attached > 0);
}

#define BATCH_SIZE 128
void *echo(void *arg)
{
	thread_ctrl *pth_ctrl = (thread_ctrl*) arg;
	int cpu_id = pth_ctrl->cpu_id;
	struct ps_handle *handle = &pth_ctrl->handle;
	int num_devices_attached = pth_ctrl->num_devices_attached;
	int* devices_attached = pth_ctrl->devices_attached;
	struct ps_chunk chunk;
	//!trace variable
	file_cache_t *fct;
	unsigned int pktlen;
	u_char *pktdata;
	//!performance variable
	uint64_t total_tx_packets = 0;
	uint64_t total_tx_bytes = 0;
	struct timeval subtime;
	int ifindex;

	int i;
	int working = 0;

	bind_cpu(cpu_id);
	assert(ps_init_handle(handle) == 0);

	//Preload pcap file --must done after bind_cpu() call. 
	if ((fct = preload_pcap_file(cpu_id)) != NULL) {
		printf("Loading done, core %d\n", cpu_id);
		if (!check_pcap(fct))
			printf("It is not trace file, core %d\n", cpu_id);
	} else {
		printf("Loading failed, core %d\n", cpu_id);
	}

	for (i = 0; i < num_devices_attached; i++) {

		if (devices[devices_attached[i]].num_tx_queues <= cpu_id) {
			printf("WARNING: xge%d has not enough TX queues!\n",
					devices_attached[i]);
			continue;
		}

		working = 1;

		printf("attaching TX queue xge%d:%d to CPU%d\n", devices_attached[i], cpu_id, cpu_id);
	}

	if (!working)
		goto done;

	assert(ps_alloc_chunk(handle, &chunk) == 0);
	
	/* initialise chunk */
	chunk.queue.qidx = cpu_id;
	chunk.cnt = BATCH_SIZE;
	chunk.recv_blocking = 1;

	printf("%d CPU: chunk.cnt = %d\n", cpu_id, chunk.cnt);
	
	/* begin to replay */
	pthread_barrier_wait(pth_ctrl->barrier);

	gettimeofday(&(pth_ctrl->starttime), NULL);
	
	while(1) {
		/* build packets */
		for (i=0; i < chunk.cnt; i++) {
retry:
			pktdata = prep_next_skb(fct, &pktlen);
			if(pktdata == NULL) {
				if(loop == 0) goto last_chunk;
				else {
					fct->offset = sizeof(pf_hdr_t);
					goto retry;
				}
			}

			chunk.info[i].offset = i * MAX_PACKET_SIZE;
			chunk.info[i].len = pktlen;
			memcpy_aligned_tx(chunk.buf + chunk.info[i].offset,
					pktdata,
					pktlen);
		}

last_chunk:
		if(i < BATCH_SIZE) 	chunk.cnt = i; 

		/* send packets */
		for (i = 0; i < num_devices_attached; i++) {

			chunk.queue.ifindex = devices_attached[i];

			int ret = ps_send_chunk(handle, &chunk);
			
			/* FIXME:never discard one packet */
			if(ret < chunk.cnt) assert(ret < chunk.cnt);

			assert(ret >= 0);
		}
		/* send over */
		if(chunk.cnt < BATCH_SIZE) break;

		/* dynamic show performance */
		if(loop == 1) {
			total_tx_packets = 0;
			total_tx_bytes = 0;
			for (i = 0; i < num_devices_attached; i++) {
				ifindex = devices_attached[i];
				total_tx_packets += handle->tx_packets[ifindex];
				total_tx_bytes += handle->tx_bytes[ifindex];
			}
			if(total_tx_packets % 2000000 < 100) { 

				gettimeofday(&(pth_ctrl->endtime), NULL);
				timersub(&pth_ctrl->endtime, &pth_ctrl->starttime, &subtime);

				printf("CPU %d: %ld packets transmitted, elapse time : %lds/%ldus Send Speed : %lf Mpps, %5.2f Gbps(payload), Aveage Len. = %ld\n", 
						cpu_id, total_tx_packets, subtime.tv_sec, subtime.tv_usec, 
						(double)(total_tx_packets) / (double) (subtime.tv_sec*1000000+subtime.tv_usec),
						(double)(total_tx_bytes*8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
						total_tx_bytes/total_tx_packets);
			}
			
		} /* end performance */ 

	} /* external loop */
	
	gettimeofday(&(pth_ctrl->endtime), NULL);
	timersub(&pth_ctrl->endtime, &pth_ctrl->starttime, &subtime);

	printf("%d CPU: last chunk %d packets\n", cpu_id, chunk.cnt);

	/* performance statistics */
	total_tx_packets = 0;
	total_tx_bytes = 0;
	for (i = 0; i < num_devices_attached; i++) {
		ifindex = devices_attached[i];
		total_tx_packets += handle->tx_packets[ifindex];
		total_tx_bytes += handle->tx_bytes[ifindex];
	}

	printf("CPU %d: %ld packets transmitted, elapse time : %lds/%ldus Send Speed : %lf Mpps, %5.2f Gbps(payload), Aveage Len. = %ld\n", 
			cpu_id, total_tx_packets, subtime.tv_sec, subtime.tv_usec, 
			(double)(total_tx_packets) / (double) (subtime.tv_sec*1000000+subtime.tv_usec),
			(double)(total_tx_bytes*8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000),
			total_tx_bytes/total_tx_packets);

	
	tot_packets[cpu_id] = total_tx_packets;
	tot_gbps[cpu_id] = (double)(total_tx_bytes*8) / (double) ((subtime.tv_sec*1000000+subtime.tv_usec) * 1000);
	tot_mpps[cpu_id] = (double)(total_tx_packets) / (double) (subtime.tv_sec*1000000+subtime.tv_usec);

	for (i = 0; i < num_devices_attached; i++) {
		char *dev = devices[devices_attached[i]].name;
		ifindex = devices_attached[i];

		if (handle->tx_packets[ifindex] == 0)
			continue;

		printf("  %s: ", dev);
		
		printf("TX %ld packets "
				"(%ld chunks, %.2f packets per chunk)\n", 
				handle->tx_packets[ifindex],
				handle->tx_chunks[ifindex],
				handle->tx_packets[ifindex] / 
				  (double)handle->tx_chunks[ifindex]);
	}

done:
	ps_close_handle(handle);

	return 0;
}


int main(int argc, char **argv)
{
	int num_cpus;
	int i ;

	num_cpus = get_num_cpus();
	assert(num_cpus >= 1);

	num_devices = ps_list_devices(devices);
	if (num_devices == -1) {
		perror("ps_list_devices");
		exit(1);
	}

	parse_opt(argc, argv);

	pthread_barrier_init(&barrier, NULL, num_cpus);

	for (i = 0; i < num_cpus; i ++) { 
		th_ctrl[i].cpu_id = i;
		th_ctrl[i].barrier = &barrier;
		th_ctrl[i].num_devices_attached = num_devices_attached;
		memcpy(th_ctrl[i].devices_attached, devices_attached, sizeof(int) * MAX_DEVICES);
		int ret = pthread_create(&(th_ctrl[i].th_ctrl), NULL, echo, (void*)&(th_ctrl[i]));
		assert(ret == 0);	
	}

	for(i = 0; i < num_cpus; i++)
		pthread_join(th_ctrl[i].th_ctrl, NULL);

	long packets = 0;
	double gbps = 0;
	double mpps = 0;
	for(i = 0; i < num_cpus; i++) { 
		packets += tot_packets[i];
		gbps += tot_gbps[i];
		mpps += tot_mpps[i];
	}
	printf("-----------------------\n");
	printf("tot_packets: %ld, tot_gbps: %lf, tot_mpps: %lf\n", packets, gbps, mpps);
	return 0;
}
