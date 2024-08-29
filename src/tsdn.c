#include "tsdn.h"

Bool internal_src = TRUE;
Bool internal_dst = TRUE;

Bool warn_printtrunc = TRUE;

/* option flags and default values */
Bool live_flag = TRUE;

/* Interaction with pcap */
static struct ether_header eth_header;
#define EH_SIZE sizeof(struct ether_header)

static char *eth_buf; 
static char *ip_buf; /* [IP_MAXPACKET] */
static void *callback_plast;

struct pcap_pkthdr *callback_phdr;

struct timeval current_time;

int debug = 3;

static u_long pcount = 0; // global packet counter
static u_long fpnum = 0;  // per file packet counter
static int file_count = 0;

u_long pnum = 0;

/* global pointer, the pcap info header */
static pcap_t *pcap;

struct in_addr *internal_net_list;
int *internal_net_mask;
int tot_internal_nets;

/* pkt_rx thread */
static int
my_callback(char *user, struct pcap_pkthdr *phdr, unsigned char *buf)
{
	int type;
	int iplen;
	static int offset = -1;

	timeval current_time;
	int time_diff;

	iplen = phdr->caplen;
	if (iplen > IP_MAXPACKET)
		iplen = IP_MAXPACKET;

	type = pcap_datalink(pcap);

	/* remember the stuff we always save */
	callback_phdr = phdr;
	pcap_current_hdr = *phdr;
	pcap_current_buf = buf;

	// if (debug > 2)
	// 	fprintf(fp_stderr, "tcpdump: read a type %d IP frame\n", type);

	/* kindof ugly, but about the only way to make them fit together :-( */
	switch (type)
	{
	case 100:
		/* for some reason, the windows version of tcpdump is using */
		/* this.  It looks just like ethernet to me */
	case PCAP_DLT_EN10MB:
		// offset = find_ip_eth(buf); /* Here we check if we are dealing with Straight Ethernet encapsulation or PPPoE */
		offset = 14;
		iplen -= offset;
		// memcpy(&eth_header, buf, EH_SIZE); /* save ether header */
		
		eth_buf = buf;
		/* now get rid of ethernet headers */
		switch (offset)
		{
		case -1: /* Not an IP packet */
			return (-1);
		case EH_SIZE: /* straight Ethernet encapsulation */
			ip_buf = (char *)(buf + offset);
			callback_plast = ip_buf + iplen - 1;
			break;
		default: /* should not be used, but we never know ... */
			return (-1);
		}
		break;

	default:
		fprintf(fp_stderr, "Don't understand link-level format (%d)\n", type);
		exit(1);
	}

	return (0);
}

int pread_tcpdump(struct timeval *ptime,
				  int *plen,
				  int *ptlen,
				  struct ether_header **pphys, int *pphystype, struct ip **ppip, void **pplast)
{
	int ret;
	while (1)
	{

		if ((ret = pcap_dispatch(pcap, 1, (pcap_handler)my_callback, 0)) != 1)
		{
			/* prob EOF */

			if (ret == -1)
			{
				char *error;
				error = pcap_geterr(pcap);

				if (error && *error)
					fprintf(fp_stderr, "PCAP error: '%s'\n", pcap_geterr(pcap));
				/* else, it's just EOF */
				return (-1);
			}

			/* in live capture is just a packet filter by kernel */
			if (live_flag)
				continue;

			/* from a file itshould be an EOF */
			return (0);
		}

		/* fill in all of the return values */
		// *pphys = &eth_header;	 /* everything assumed to be ethernet */
		*pphys = (struct ether_header *)eth_buf;
		*pphystype = PHYS_ETHER; /* everything assumed to be ethernet */
		*ppip = (struct ip *)ip_buf;
		*pplast = callback_plast; /* last byte in IP packet */

		/* use the real time from Libpcap */
		ptime->tv_usec = pcap_current_hdr.ts.tv_usec;
		ptime->tv_sec = pcap_current_hdr.ts.tv_sec;
		*plen = pcap_current_hdr.len;
		*ptlen = pcap_current_hdr.caplen;

		/* if it's not IP, then skip it */
		if ((ntohs(eth_header.ether_type) != ETHERTYPE_IP) &&
			(ntohs(eth_header.ether_type) != ETHERTYPE_IPV6))
		{
			if (debug > 2)
				fprintf(fp_stderr, "pread_tcpdump: not an IP packet\n");
			continue;
		}

		return (1);
	}
}

// return 0: packet skipped
// return 1: packet analized
static int ProcessPacket(struct timeval *pckt_time,
						 struct ip *pip,
						 void *plast,
						 int tlen,
						 struct ether_header *peth,
						 int phystype,
						 u_long *fpnum,
						 u_long *pcount,
						 int file_count,
						 long int location,
						 int ip_direction)
{
	/* Header defintion */
	struct icmphdr *picmp = NULL;

	/* quick sanity check, better be an IPv4/v6 packet */
	if (!PIP_ISV4(pip) && !PIP_ISV6(pip))
	{
		static Bool warned = FALSE;
		if (!warned)
		{
			fprintf(fp_stderr, "Warning: saw at least one non-ip packet\n");
			warned = TRUE;
		}
		if (debug > 1)
#ifdef SUPPORT_IPV6
			fprintf(fp_stderr,
					"Skipping packet %lu, not an IPv4/v6 packet (version:%d)\n",
					pnum, pip->ip_v);
#else
			fprintf(fp_stderr,
					"Skipping packet %lu, not an IPv4 packet (version:%d)\n",
					pnum, pip->ip_v);
#endif
		return 0;
	}

	/* If it's IP-over-IP, skip the external IP header */
	if (PIP_ISV4(pip) && (pip->ip_p == IPPROTO_IPIP || pip->ip_p == IPPROTO_IPV6))
	{
		pip = (struct ip *)((char *)pip + 4 * pip->ip_hl);
		if (!PIP_ISV4(pip) && !PIP_ISV6(pip))
		{
			/* The same sanity check than above, but without warnings*/
			return 0;
		}
	}

	// /* Check if the packet is from/to an internal network */
	// internal_ip(pip->ip_src);
	// internal_ip(pip->ip_dst);

	/* Check the IP protocol ICMP/TCP/UDP */
	switch (pip->ip_p)
	{
	case IPPROTO_TCP:
	{
		struct tcphdr *ptcp = NULL;
		if ((ptcp = gettcp(pip, &plast)) != NULL)
		{
			pkt_handle(peth, pip, ptcp, plast, pckt_time);
		}
		break;
	}
	case IPPROTO_UDP:
	{
		struct udphdr *pudp = NULL;
		if ((pudp = getudp(pip, &plast)) != NULL)
		{
			pkt_handle(peth, pip, pudp, plast, pckt_time);
		}
		break;
	}
	case IPPROTO_ICMP:
	{	
		struct icmphdr *picmp = NULL;
		if ((picmp = geticmp(pip, &plast)) != NULL)
		{
			pkt_handle(peth, pip, picmp, plast, pckt_time);
		}
		break;
	}

	default:
		fprintf(fp_stderr, "ProcessPacket: Un-supported IP Protocol!");
		break;
	}

	return 1;
}

int main(int argc, char *argv[])
{
	InitGlobalArrays();
	/* initialize internals */
	trace_init();

	/* The relative path here is valid only when the tsdn is executed at the project root directory. */
	LoadInternalNets("conf/net.internal");

	char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
	struct bpf_program fp;		   /* The compiled filter */
	// char filter_exp[] = "(tcp[13] & 2 != 0) || \
	// 					(tcp[13] & 4 != 0) || \
	// 					(tcp[13] & 16 != 0) || \
	// 					(icmp[icmptype] = 0) || \
	// 					(icmp[icmptype] = 8) || \
	// 					(udp) ";   /* The filter expression */
	char filter_exp[] = "ip";
	struct pcap_pkthdr header; /* The header that pcap gives us */
	struct ether_header *eptr; /* net/ethernet.h */
	u_char *ptr;			   /* printing out hardware header info */
	const u_char *packet;	   /* The actual packet */
	// pcap_if_t *all_devs;

	int ret = 0;
	struct ip *pip;
	int phystype;
	struct ether_header *phys; /* physical transport header */
	int fix;
	int len;
	int tlen;
	void *plast;
	long int location = 0;

	// /* Define the device */
	// if (pcap_findalldevs(&all_devs, errbuf) == -1)
	// {
	// 	fprintf(stderr, "error finding devices");
	// 	return 1;
	// }
	// dev = all_devs->name;
	// // or loop through all_devs to find the one you want
	// if (all_devs == NULL)
	// {
	// 	printf("Error finding devices: %s\n", errbuf);
	// 	return 1;
	// }

	printf("Capturing on the device: %s\n", RECV_INTF);

	/* open the device for sniffing. Here we use create+activate rather to avoid the packet buffer in libpcap. */
	// pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	pcap = pcap_create(RECV_INTF, errbuf);

	/* Set immediate mode */
	if (pcap_set_immediate_mode(pcap, 1) == -1)
	{
		fprintf(stderr, "Error setting immediate mode\n");
		return 1;
	}

	/* Activate the pcap handle. */
	if (pcap_activate(pcap) == -1)
	{
		fprintf(stderr, "Error activating pcap\n");
		return (2);
	}

	if (pcap == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", RECV_INTF, errbuf);
		return (2);
	}

	/* Compile the filter represented by string*/
	if (pcap_compile(pcap, &fp, filter_exp, 1, 0) == -1)
	{
		fprintf(stderr, "Error calling pcap_compile\n");
		return (2);
	}

	/* set the compiled program as the filter */
	if (pcap_setfilter(pcap, &fp) == -1)
	{
		fprintf(stderr, "Error setting filter\n");
		return (2);
	}

	memset(&eth_header, 0, EH_SIZE);
	eth_header.ether_type = htons(ETHERTYPE_IP);
	ip_buf = MallocZ(IP_MAXPACKET);

	/* Use three threads to manage three levels of timeout */
	/* timeout_level_1 thread */
	pthread_t timeout_level_1_thread;
	timeout_mgmt_args timeout_level_1_args = {TIMEOUT_LEVEL_1, circ_buf_list[0], &circ_buf_mutex_list[0], &circ_buf_cond_list[0], &circ_buf_head_mutex_list[0]};
	if (pthread_create(&timeout_level_1_thread, NULL, timeout_mgmt, (void*)&timeout_level_1_args))
	{
		fprintf(stderr, "Error creating timeout_level_1 thread\n");
		return 1;
	}

	/* timeout_level_2 thread */
	pthread_t timeout_level_2_thread;
	timeout_mgmt_args timeout_level_2_args = {TIMEOUT_LEVEL_2, circ_buf_list[1], &circ_buf_mutex_list[1], &circ_buf_cond_list[1], &circ_buf_head_mutex_list[1]};
	if (pthread_create(&timeout_level_2_thread, NULL, timeout_mgmt, (void*)&timeout_level_2_args))
	{
		fprintf(stderr, "Error creating timeout_level_2 thread\n");
		return 1;
	}

	/* timeout_level_3 thread */
	pthread_t timeout_level_3_thread;
	timeout_mgmt_args timeout_level_3_args = {TIMEOUT_LEVEL_3, circ_buf_list[2], &circ_buf_mutex_list[2], &circ_buf_cond_list[2], &circ_buf_head_mutex_list[2]};
	if (pthread_create(&timeout_level_3_thread, NULL, timeout_mgmt, (void*)&timeout_level_3_args))
	{
		fprintf(stderr, "Error creating timeout_level_3 thread\n");
		return 1;
	}

	/* lazy freeing thread */
	pthread_t lazy_free_flow_hash_thread;
	if (pthread_create(&lazy_free_flow_hash_thread, NULL, lazy_free_flow_hash, NULL))
	{
		fprintf(stderr, "Error creating lazy_free_flow_hash thread\n");
		return 1;
	}

	/* pkt_rx thread */
	ret = pread_tcpdump(&current_time, &len, &tlen, &phys, &phystype, &pip,
						&plast);

#ifdef PCAP_DEBUG
	int i = 0;
	do
	{
		ProcessPacket(&current_time, pip, plast, tlen, phys, phystype, &fpnum, &pcount,
					  file_count, location, DEFAULT_NET);
		i++;
	} while ((ret = pread_tcpdump(&current_time, &len, &tlen, &phys, &phystype, &pip, &plast) > 0) && i < 100);
#else
	do
	{
		ProcessPacket(&current_time, pip, plast, tlen, phys, phystype, &fpnum, &pcount,
					  file_count, location, DEFAULT_NET);
	} while ((ret = pread_tcpdump(&current_time, &len, &tlen, &phys, &phystype, &pip, &plast) > 0));
#endif

	/* free the circular buffer */
	for (int i = 0; i < TIMEOUT_LEVEL_NUM; i++)
	{
		free(circ_buf_list[i]->buf_space);
		free(circ_buf_list[i]);
	}

	/* free the flow hash table */
	for (int i = 0; i < HASH_TABLE_SIZE; i++)
	{
		flow_hash_t *flow_hash_ptr = flow_hash_table[i];
		while (flow_hash_ptr != NULL)
		{
			flow_hash_t *temp = flow_hash_ptr;
			flow_hash_ptr = flow_hash_ptr->next;
			free(temp);
		}
	}

	/* free the lazy flow hash table */
	for (int i = 0; i < HASH_TABLE_SIZE; i++)
	{
		flow_hash_t *flow_hash_ptr = lazy_flow_hash_buf[i];
		while (flow_hash_ptr != NULL)
		{
			flow_hash_t *temp = flow_hash_ptr;
			flow_hash_ptr = flow_hash_ptr->next;
			free(temp);
		}
	}

	/* Release the mutex */
	for (int i = 0; i < TIMEOUT_LEVEL_NUM; i++)
	{
		pthread_mutex_destroy(&circ_buf_mutex_list[i]);
		pthread_cond_destroy(&circ_buf_cond_list[i]);
	}
	pthread_mutex_destroy(&lazy_flow_hash_mutex);
	pthread_cond_destroy(&lazy_flow_hash_cond);

	pthread_cancel(timeout_level_1_thread);
	pthread_cancel(timeout_level_2_thread);
	pthread_cancel(timeout_level_3_thread);
	pthread_cancel(lazy_free_flow_hash_thread);
	return 0;
}

void *
MallocZ(int nbytes)
{
	char *ptr;

	// ptr = malloc(nbytes);
	ptr = calloc(1, nbytes);
	if (ptr == NULL)
	{
		fprintf(fp_stderr, "Malloc failed, fatal: %s\n", strerror(errno));
		fprintf(fp_stderr,
				"when memory allocation fails, it's either because:\n"
				"1) You're out of swap space, talk to your local "
				"sysadmin about making more\n"
				"(look for system commands 'swap' or 'swapon' for quick fixes)\n"
				"2) The amount of memory that your OS gives each process "
				"is too little\n"
				"That's a system configuration issue that you'll need to discuss\n"
				"with the system administrator\n");
		exit(EXIT_FAILURE);
	}

	// memset(ptr, 0, nbytes); /* BZERO */
	return (ptr);
}
