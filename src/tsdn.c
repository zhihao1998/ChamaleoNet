#include "tsdn.h"

Bool internal_src = TRUE;
Bool internal_dst = TRUE;

/* option flags and default values */
Bool live_flag = TRUE;

/* Interaction with pcap */
#define EH_SIZE sizeof(struct ether_header)

static char *eth_buf;
static char *ip_buf;
static void *callback_plast;

/* Buffer some packets of tcpdump to avoid packet loss */
circular_buf_t *pkt_buf;

struct pcap_pkthdr pcap_current_hdr;
unsigned char *pcap_current_buf;
struct pcap_pkthdr *callback_phdr;

/* Timer for check expired packet (timeout mechanism) */
struct timeval last_pkt_cleaned_time;
struct timeval current_time;
struct timeval last_log_time;

/* Timer for lazy free */
struct timeval last_hash_cleaned_time;

/* Timer for cleaning idle entries */
struct timeval last_idle_cleaned_time;

#ifdef DO_STATS
void stats_init()
{
	pkt_count = 0;

	tcp_pkt_count_tot = 0;
	// u_long in_tcp_pkt_count;
	// u_long out_tcp_pkt_count;
	// u_long local_tcp_pkt_count;

	udp_pkt_count_tot = 0;
	// u_long in_udp_pkt_count;
	// u_long out_udp_pkt_count;
	// u_long local_udp_pkt_count;

	icmp_pkt_count_tot = 0;
	// u_long in_icmp_pkt_count;
	// u_long out_icmp_pkt_count;
	// u_long local_icmp_pkt_count;

	unsupported_pkt_count = 0;
	send_pkt_error_count = 0;

	// Data Structure Counters
	pkt_buf_count = 0;
	flow_hash_count = 0;
	lazy_flow_hash_count = 0;
	lazy_flow_hash_hit = 0;

	// Freelist Counters
	pkt_list_count_tot = 0;
	pkt_list_count_use = 0;
	flow_hash_list_count_tot = 0;
	flow_hash_list_count_use = 0;

	flow_hash_search_depth = 0;

	// Functionality Counters
	installed_entry_count_tot = 0;
	installed_entry_count_tcp = 0;
	installed_entry_count_udp = 0;
	installed_entry_count_icmp = 0;

	install_buf_size = 0;

	replied_flow_count_tot = 0;
	replied_flow_count_tcp = 0;
	replied_flow_count_udp = 0;
	replied_flow_count_icmp = 0;

	expired_pkt_count_tot = 0;
	expired_pkt_count_tcp = 0;
	expired_pkt_count_udp = 0;
	expired_pkt_count_icmp = 0;
}
#endif

/* global pointer, the pcap info header */
static pcap_t *pcap;
struct pcap_stat stats_pcap;

struct in_addr *internal_net_list;
int *internal_net_mask;
int tot_internal_nets;

/* Multi Thread Declaration */
pthread_t entry_install_thread;

/* pkt_rx thread */
static int
my_callback(char *user, struct pcap_pkthdr *phdr, unsigned char *buf)
{
	int type;
	int iplen;
	static int offset = -1;

	iplen = phdr->caplen;

	type = pcap_datalink(pcap);

	/* remember the stuff we always save */
	callback_phdr = phdr;
	pcap_current_hdr = *phdr;
	pcap_current_buf = buf;

	switch (type)
	{
	case 100:
		/* for some reason, the windows version of tcpdump is using */
		/* this.  It looks just like ethernet to me */
	case PCAP_DLT_EN10MB:
		// offset = find_ip_eth(buf); /* Here we check if we are dealing with Straight Ethernet encapsulation or PPPoE */
		offset = ETHER_HDRLEN;
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
				  struct ether_header **pphys,
				  int *pphystype,
				  struct ip **ppip,
				  void **pplast)
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
		*pphys = (struct ether_header *)eth_buf; /* everything assumed to be ethernet */
		*pphystype = PHYS_ETHER;				 /* everything assumed to be ethernet */
		*ppip = (struct ip *)ip_buf;
		*pplast = callback_plast; /* last byte in IP packet */

		/* use the real time from Libpcap */
		ptime->tv_usec = pcap_current_hdr.ts.tv_usec;
		ptime->tv_sec = pcap_current_hdr.ts.tv_sec;
		*plen = pcap_current_hdr.len;
		*ptlen = pcap_current_hdr.caplen;

		/* if it's not IP, then skip it */
		if ((ntohs((*pphys)->ether_type) != ETHERTYPE_IP))
		{
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
						 long int location,
						 int ip_direction)
{
	/* quick sanity check, better be an IPv4/v6 packet */
	if (!PIP_ISV4(pip))
	{
		fprintf(fp_stderr,
				"Skipping a packet, not an IPv4 packet (version:%d)\n", pip->ip_v);
		return 0;
	}

	/* If it's IP-over-IP, skip the external IP header */
	if (PIP_ISV4(pip) && (pip->ip_p == IPPROTO_IPIP))
	{
		pip = (struct ip *)((char *)pip + 4 * pip->ip_hl);
		if (!PIP_ISV4(pip))
		{
			/* The same sanity check than above, but without warnings*/
			return 0;
		}
	}

	// /* Check if the packet is from/to an internal network */
	// internal_ip(pip->ip_src);
	// internal_ip(pip->ip_dst);

	/* Count the packet */
#ifdef DO_STATS
	pkt_count++;
#endif
	/* Check the IP protocol ICMP/TCP/UDP */
	switch (pip->ip_p)
	{
	case IPPROTO_TCP:
	{
		struct tcphdr *ptcp = NULL;
		if ((ptcp = gettcp(pip, &plast)) != NULL)
		{
#ifdef DO_STATS
			tcp_pkt_count_tot++;
#endif
			pkt_handle(peth, pip, ptcp, plast);
		}
		break;
	}
	case IPPROTO_UDP:
	{
		struct udphdr *pudp = NULL;
		if ((pudp = getudp(pip, &plast)) != NULL)
		{
#ifdef DO_STATS
			udp_pkt_count_tot++;
#endif
			pkt_handle(peth, pip, pudp, plast);
		}
		break;
	}
	case IPPROTO_ICMP:
	{
		struct icmphdr *picmp = NULL;
		if ((picmp = geticmp(pip, &plast)) != NULL)
		{
#ifdef DO_STATS
			icmp_pkt_count_tot++;
#endif
			pkt_handle(peth, pip, picmp, plast);
		}
		break;
	}

	default:
#ifdef DO_STATS
		unsupported_pkt_count++;
#endif
		break;
	}

	return 1;
}

void print_all_stats()
{
	printf("----------------------------------------\n");
	printf("\nDoing Statistics... \n");
	printf("pkt_count: %ld, tcp_pkt_count_tot: %ld, udp_pkt_count_tot: %ld, icmp_pkt_count_tot: %ld, unsupported_pkt_count: %ld, "
		   "pkt_buf_count: %ld, flow_hash_count: %ld, lazy_flow_hash_count: %ld, lazy_flow_hash_hit: %ld, "
		   "pkt_list_count_tot: %ld, pkt_list_count_use: %ld, flow_hash_list_count_tot: %ld, flow_hash_list_count_use: %ld, flow_hash_search_depth: %ld, "
		   "installed_entry_count_tot: %ld, installed_entry_count_tcp: %ld, installed_entry_count_udp: %ld, installed_entry_count_icmp: %ld, install_buf_size: %ld, "
		   "replied_flow_count_tot: %ld, replied_flow_count_tcp: %ld, replied_flow_count_udp: %ld, replied_flow_count_icmp: %ld, "
		   "expired_pkt_count_tot: %ld, expired_pkt_count_tcp: %ld, expired_pkt_count_udp: %ld, expired_pkt_count_icmp: %ld, "
		   "active_host_tbl_entry_count: %ld, local_entry_count: %ld, send_pkt_error_count: %ld\n",
		   pkt_count, tcp_pkt_count_tot, udp_pkt_count_tot, icmp_pkt_count_tot, unsupported_pkt_count,
		   pkt_buf_count, flow_hash_count, lazy_flow_hash_count, lazy_flow_hash_hit,
		   pkt_list_count_tot, pkt_list_count_use,
		   flow_hash_list_count_tot, flow_hash_list_count_use, flow_hash_search_depth,
		   installed_entry_count_tot, installed_entry_count_tcp, installed_entry_count_udp, installed_entry_count_icmp, install_buf_size,
		   replied_flow_count_tot, replied_flow_count_tcp, replied_flow_count_udp, replied_flow_count_icmp,
		   expired_pkt_count_tot, expired_pkt_count_tcp, expired_pkt_count_udp, expired_pkt_count_icmp,
		   active_host_tbl_entry_count, local_entry_count,
		   send_pkt_error_count);

	/* Print the statistics */
	if (pcap_stats(pcap, &stats_pcap) >= 0)
	{
		printf("\nPcap Statistics\n");
		printf("Received: %d, Dropped: %d, Dropped by interface: %d\n", stats_pcap.ps_recv, stats_pcap.ps_drop, stats_pcap.ps_ifdrop);
	}
}

void clean_all()
{
	/* free all data structure */
	trace_cleanup();
	/* close pcap */
	pcap_close(pcap);
	/* close bfrt_grpc */
	bfrt_grpc_destroy();
	/* close log */
#ifdef LOG_TO_FILE
	fclose(fp_log);
	fclose(fp_stats);
#endif
}

void sig_proc(int sig)
{
	print_all_stats();
	clean_all();
	exit(0);
}

void init_log()
{
	time_t t;
	struct tm *tm;
	t = time(NULL);
	tm = localtime(&t);

	char log_dir[100];
	sprintf(log_dir, "log");
	// sprintf(log_dir, "log/log_%d-%d", tm->tm_mon + 1, tm->tm_mday);
	// mkdir(log_dir, 0777);

	char log_file_name[200], stat_file_name[200], param_file_name[200];
	sprintf(param_file_name, "%s/buf%d_GCsize%d_GCperiod%d_T%d_param.txt", log_dir, PKT_BUF_SIZE, PKT_BUF_GC_SPLIT_SIZE, PKT_BUF_GC_PERIOD, PKT_TIMEOUT);
	FILE *fp_param = fopen(param_file_name, "w");
	/* Record all parameters to param file */
	fprintf(fp_param, "PKT_BUF_SIZE: %d\n", PKT_BUF_SIZE);
	fprintf(fp_param, "PKT_BUF_GC_SPLIT_SIZE: %d\n", PKT_BUF_GC_SPLIT_SIZE);
	fprintf(fp_param, "PKT_BUF_GC_PERIOD: %d\n", PKT_BUF_GC_PERIOD);
	fprintf(fp_param, "PKT_TIMEOUT: %d\n", PKT_TIMEOUT);

	fprintf(fp_param, "FLOW_HASH_TABLE_SIZE: %d\n", FLOW_HASH_TABLE_SIZE);
	fprintf(fp_param, "FLOW_HASH_TABLE_GC_SIZE: %d\n", FLOW_HASH_TABLE_GC_SIZE);
	fprintf(fp_param, "FLOW_HASH_TABLE_GC_PERIOD: %d\n", FLOW_HASH_TABLE_GC_PERIOD);
	fprintf(fp_param, "FLOW_HASH_TABLE_GC_TIMEOUT: %d\n", FLOW_HASH_TABLE_GC_TIMEOUT);

	fprintf(fp_param, "ENTRY_BUF_SIZE: %d\n", ENTRY_BUF_SIZE);
	fprintf(fp_param, "ENTRY_INSTALL_BATCH_SIZE: %d\n", ENTRY_INSTALL_BATCH_SIZE);
	fprintf(fp_param, "ENTRY_IDLE_TIMEOUT: %d\n", ENTRY_IDLE_TIMEOUT);
	fprintf(fp_param, "ENTRY_IDLE_CLEAN_BATCH_SIZE: %d\n", ENTRY_IDLE_CLEAN_BATCH_SIZE);
	fprintf(fp_param, "ENTRY_GC_PERIOD: %d\n", ENTRY_GC_PERIOD);

	fprintf(fp_param, "PKT_LOG_SAMPLE_CNT: %d\n", PKT_LOG_SAMPLE_CNT);
	fprintf(fp_param, "TIMEOUT_SAMPLE_CNT: %d\n", TIMEOUT_SAMPLE_CNT);
	fprintf(fp_param, "STATS_LOG_SAMPLE_TIME: %d\n", STATS_LOG_SAMPLE_TIME);

	fclose(fp_param);

#ifdef LOG_TO_FILE
	sprintf(log_file_name, "%s/buf%d_GCsize%d_GCperiod%d_T%d_log.txt", log_dir, PKT_BUF_SIZE, PKT_BUF_GC_SPLIT_SIZE, PKT_BUF_GC_PERIOD, PKT_TIMEOUT);
	sprintf(stat_file_name, "%s/buf%d_GCsize%d_GCperiod%d_T%d_stat.csv", log_dir, PKT_BUF_SIZE, PKT_BUF_GC_SPLIT_SIZE, PKT_BUF_GC_PERIOD, PKT_TIMEOUT);

	fp_log = fopen(log_file_name, "w");
	fp_stats = fopen(stat_file_name, "w");
	fprintf(fp_stats, "time,level,file,line,msg,"
					  "pkt_count,tcp_pkt_count_tot,udp_pkt_count_tot,icmp_pkt_count_tot,unsupported_pkt_count,"
					  "pkt_buf_count,flow_hash_count,lazy_flow_hash_count,lazy_flow_hash_hit,"
					  "pkt_list_count_tot,pkt_list_count_use,"
					  "flow_hash_list_count_tot,flow_hash_list_count_use,flow_hash_search_depth,"
					  "installed_entry_count_tot,installed_entry_count_tcp,installed_entry_count_udp,installed_entry_count_icmp,install_buf_size,"
					  "replied_flow_count_tot,replied_flow_count_tcp,replied_flow_count_udp,replied_flow_count_icmp,"
					  "expired_pkt_count_tot,expired_pkt_count_tcp,expired_pkt_count_udp,expired_pkt_count_icmp,"
					  "active_host_tbl_entry_count,local_entry_count,send_pkt_error_count\n");
	log_add_fp(fp_stats, LOG_STATS);
#endif
	log_set_quiet(TRUE);
}

int main(int argc, char *argv[])
{

	InitGlobalArrays();
	/* parse the flags */
	// CheckArguments(&argc, argv);

	/* initialize  */
	trace_init();
	init_log();

	LoadInternalNets("conf/net.internal");
	// LoadGlobals("conf/globals.conf");

	char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
	struct bpf_program fp;		   /* The compiled filter */
	char filter_exp[] = "ip";
	struct pcap_pkthdr header; /* The header that pcap gives us */
	struct ether_header *eptr; /* net/ethernet.h */
	u_char *ptr;			   /* printing out hardware header info */
	const u_char *packet;	   /* The actual packet */

	int ret = 0;
	struct ip *pip;
	int phystype;
	struct ether_header *phys; /* physical transport header */
	int fix;
	int len;
	int tlen;
	void *plast;
	long int location = 0;

	printf("Capturing on the device: %s\n", RECV_INTF);

	/* Capture the Ctrl+C single */
	signal(SIGINT, sig_proc);

	/* open the device for sniffing. Here we use create+activate rather to avoid the packet buffer in libpcap. */
	// pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	pcap = pcap_create(RECV_INTF, errbuf);

	/* Set immediate mode */
	if (pcap_set_immediate_mode(pcap, 1) == -1)
	{
		fprintf(stderr, "Error setting immediate mode\n");
		return 1;
	}

	if (pcap_set_buffer_size(pcap, 2000000000) == -1)
	{
		fprintf(stderr, "Error setting buffer size\n");
		return (2);
	}

	/* set the snap length of pcap */
	if (pcap_set_snaplen(pcap, SNAP_LEN) == -1)
	{
		fprintf(stderr, "Error setting snap length\n");
		return (2);
	}

	if (pcap_set_promisc(pcap, 1) != 0)
	{
		fprintf(stderr, "Error setting promiscuous mode\n");
		return (2);
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

	fprintf(stderr, "libpcap version: %s, snap length %d\n",
			pcap_lib_version(),
			pcap_snapshot(pcap));

	ip_buf = MallocZ(ETHERNET_MTU);

	/* install P4 table entry thread */

	if (pthread_create(&entry_install_thread, NULL, install_thead_main, NULL))
	{
		fprintf(stderr, "Error creating entry_install_thread thread\n");
		return 1;
	}

	ret = pread_tcpdump(&current_time, &len, &tlen, &phys, &phystype, &pip,
						&plast);
	last_idle_cleaned_time = last_hash_cleaned_time = last_pkt_cleaned_time = last_log_time = current_time;

	struct timeval pkt_process_start_time, pkt_process_end_time;
	struct timeval pkt_process_end_time_tmp = current_time;

	do
	{

		ProcessPacket(&current_time, pip, plast, tlen, phys, phystype, location, DEFAULT_NET);

#ifdef DO_STATS
		if (tv_sub_2(current_time, last_log_time) > STATS_LOG_SAMPLE_TIME)
		{
			last_log_time = current_time;
			install_buf_size = entry_circ_buf_size();

#ifdef LOG_TO_FILE
			log_stats("stats,%ld,%ld,%ld,%ld,%ld,"
					  "%ld,%ld,%ld,%ld,"
					  "%ld,%ld,%ld,%ld,%ld,"
					  "%ld,%ld,%ld,%ld,%ld,"
					  "%ld,%ld,%ld,%ld,"
					  "%ld,%ld,%ld,%ld,"
					  "%ld,%ld,%ld",
					  pkt_count, tcp_pkt_count_tot, udp_pkt_count_tot, icmp_pkt_count_tot, unsupported_pkt_count,
					  pkt_buf_count, flow_hash_count, lazy_flow_hash_count, lazy_flow_hash_hit,
					  pkt_list_count_tot, pkt_list_count_use, flow_hash_list_count_tot, flow_hash_list_count_use, flow_hash_search_depth,
					  installed_entry_count_tot, installed_entry_count_tcp, installed_entry_count_udp, installed_entry_count_icmp, install_buf_size,
					  replied_flow_count_tot, replied_flow_count_tcp, replied_flow_count_udp, replied_flow_count_icmp,
					  expired_pkt_count_tot, expired_pkt_count_tcp, expired_pkt_count_udp, expired_pkt_count_icmp,
					  active_host_tbl_entry_count, local_entry_count, send_pkt_error_count);
#endif
		}
		if (pkt_count % PKT_LOG_SAMPLE_CNT == 0)
		{
#ifdef LOG_TO_FILE
			gettimeofday(&pkt_process_end_time, NULL);

			log_stats("batch_processing_time,%d,%d", pkt_count, tv_sub_2(pkt_process_end_time, pkt_process_end_time_tmp));
			log_stats("pkt_processing_time,%d,%d", pkt_count, tv_sub_2(pkt_process_end_time, current_time));
			gettimeofday(&pkt_process_end_time_tmp, NULL);
#endif
			if (pkt_count % 500000 == 0)
			{
				print_all_stats();
			}
		}
#endif
	} while ((ret = pread_tcpdump(&current_time, &len, &tlen, &phys, &phystype, &pip, &plast) > 0));

	/* Release the mutex */
	pthread_cancel(entry_install_thread);
	bfrt_grpc_destroy();
	trace_cleanup();
#ifdef LOG_TO_FILE
	fclose(fp_log);
	fclose(fp_stats);
#endif
	return 0;
}
