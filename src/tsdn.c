#include "tsdn.h"
#include "stats_print.h"

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

struct timeval last_lazy_free_log_time;

/* Print stats */
Stats stats_snapshot(void)
{
	Stats s = (Stats){0};

#define X_U64(name) s.name = (uint64_t)(name);
#define X_DBL(name) s.name = (double)(name);
#include "stats_fields.def"
#undef X_U64
#undef X_DBL

	return s;
}

#ifdef FLOW_HASH_MEASURE
void flow_hash_stats_init(void)
{
	flow_hash_total_lookups = 0;
	flow_hash_collision_lookups = 0;
	flow_hash_missed_lookups = 0;
	flow_hash_total_probes = 0;
	flow_hash_max_depth = 0;
	flow_hash_avg_probes = 0;
	flow_hash_p99_depth = 0;
	memset(flow_hash_depth_hist, 0, sizeof(flow_hash_depth_hist));
}
void flow_hash_stats_cal(void)
{
	uint64_t target = (flow_hash_total_lookups * 99 + 99) / 100;
	uint64_t acc = 0;
	for (uint32_t d = 0; d <= FLOW_HASH_MAX_DEPTH; d++)
	{
		acc += flow_hash_depth_hist[d];
		if (acc >= target)
		{
			flow_hash_p99_depth = d;
			break;
		}
	}
	if (flow_hash_total_lookups > 0)
	{
		flow_hash_avg_probes = (double)flow_hash_total_probes /
							   (double)flow_hash_total_lookups;
	}
}
#endif

void stats_init()
{
	pkt_count = 0;

	tcp_pkt_count_tot = 0;
	// uint64_t in_tcp_pkt_count;
	// uint64_t out_tcp_pkt_count;
	// uint64_t local_tcp_pkt_count;

	udp_pkt_count_tot = 0;
	// uint64_t in_udp_pkt_count;
	// uint64_t out_udp_pkt_count;
	// uint64_t local_udp_pkt_count;

	icmp_pkt_count_tot = 0;
	// uint64_t in_icmp_pkt_count;
	// uint64_t out_icmp_pkt_count;
	// uint64_t local_icmp_pkt_count;

	send_pkt_error_count = 0;

	// Data Structure Counters
	pkt_buf_count = 0;
	flow_hash_count = 0;
	lazy_flow_hash_count = 0;

	// Freelist Counters
	pkt_list_count_tot = 0;
	pkt_list_count_use = 0;
	flow_hash_list_count_tot = 0;
	flow_hash_list_count_use = 0;

	// Functionality Counters
	installed_entry_count_tot = 0;
	// installed_entry_count_tcp = 0;
	// installed_entry_count_udp = 0;
	// installed_entry_count_icmp = 0;

	install_buf_size = 0;

	entry_install_error_count = 0;
	entry_install_dedup_count = 0;

	replied_flow_count_tot = 0;
	install_rule_batch_count = 0;
	// replied_flow_count_tcp = 0;
	// replied_flow_count_udp = 0;
	// replied_flow_count_icmp = 0;

	expired_pkt_count_tot = 0;
	expired_pkt_count_tcp = 0;
	expired_pkt_count_udp = 0;
	expired_pkt_count_icmp = 0;
#ifdef FLOW_HASH_MEASURE
	flow_hash_stats_init();
#endif
}

/* global pointer, the pcap info header */
static pcap_t *pcap;
struct pcap_stat stats_pcap;

struct in_addr *internal_net_list;
int *internal_net_mask;
int tot_internal_nets;

struct in_addr *responder_net_list;
int *responder_net_mask;
int tot_responder_nets;

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

#ifdef MAX_CAPTURE_PKTS
		if (pkt_count >= (uint64_t)MAX_CAPTURE_PKTS)
		{
			return 0;
		}
#endif

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

	/* Check if the packet is from/to a darknet network, directly send out */
	if (responder_ip(pip->ip_dst) || responder_ip(pip->ip_src))
	{
		// printf("packets to responder %s ->", inet_ntoa(pip->ip_src));
		// printf(" %s, proto %d \n", inet_ntoa(pip->ip_dst), pip->ip_p);

		/* directly send out */
		if (SendPkt((char *)peth, tlen) == -1)
		{
			send_pkt_error_count++;
		}
		return 0;
		// }
		// else if ()
		// {
		// 	// printf("packets from responder %s ->", inet_ntoa(pip->ip_src));
		// 	// printf(" %s, proto %d dropping\n", inet_ntoa(pip->ip_dst), pip->ip_p);
		// 	return 0;
	}

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
		break;
	}

#ifdef HOST_LIVENESS_MONITOR
	// update host liveness based on the outbound packet
	if (internal_ip(pip->ip_src))
	{
		uint32_t ip_src = ntohl(pip->ip_src.s_addr);
		uint32_t offset = ip_src - base_ip_int;
		active_internal_host_send[offset] = 1;
	}
	else
	{
		uint32_t ip_dst = ntohl(pip->ip_dst.s_addr);
		uint32_t offset = ip_dst - base_ip_int;

		uint8_t host_alive = check_internal_host_liveness(ip_dst);
		// printf("%" PRIu32 " ,%" PRIu32 " ,%" PRIu32 ", %" PRIu8 "\n", ip_dst, base_ip_int, offset, host_alive);
		// add aliveness to header
		append_host_alive_to_tos(peth, pip, tlen, host_alive);
	}
#endif
	return 1;
}

void print_all_stats()
{
	Stats s = stats_snapshot();
	stats_print(stdout, &s, STATS_FMT_KV, 0);

	/* Print the statistics */
	if (pcap_stats(pcap, &stats_pcap) >= 0)
	{
		printf("\n%ld.%ld Pcap Statistics\n", current_time.tv_sec, current_time.tv_usec);
		printf("Received: %d, Processed: %ld, Still in queue: %ld, Dropped: %d, Dropped by interface: %d\n",
			   stats_pcap.ps_recv, pkt_count, (stats_pcap.ps_recv - pkt_count), stats_pcap.ps_drop, stats_pcap.ps_ifdrop);
	}
}

void clean_all()
{
	/* free all data structure */
	trace_cleanup();
	/* close pcap */
	pcap_close(pcap);
	/* close bfrt_grpc */
	pthread_cancel(entry_install_thread);
	/* close log */
#ifdef LOG_TO_FILE
	// fclose(fp_log);
	fclose(fp_stats);
#endif
}

static volatile sig_atomic_t g_stop = 0;

void sig_proc(int sig)
{
	Stats s = stats_snapshot();
	log_stats("stats,%s", stats_to_csv_string(&s));

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
	sprintf(log_dir, "/home/zhihaow/codes/honeypot_c_controller/log");
	char log_date[100];
	sprintf(log_date, "%d%02d%02d_%02d-%02d-%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

	char log_file_name[300], stat_file_name[300], param_file_name[300];

#ifdef LOG_TO_FILE
	// sprintf(log_file_name, "%s/%s_buf%d_GCsize%d_GCperiod%d_T%d_log.txt", log_dir, log_date, PKT_BUF_SIZE, PKT_BUF_GC_SPLIT_SIZE, PKT_BUF_GC_PERIOD, PKT_TIMEOUT);
	// sprintf(stat_file_name, "%s/%s_buf%d_GCsize%d_GCperiod%d_T%d_stat.csv", log_dir, log_date, PKT_BUF_SIZE, PKT_BUF_GC_SPLIT_SIZE, PKT_BUF_GC_PERIOD, PKT_TIMEOUT);
	sprintf(stat_file_name, "%s/%s_HashSize%d_GCSize%d_GCPeriod%d_GCTimeout%d.csv", log_dir, log_date,
			FLOW_HASH_TABLE_SIZE, FLOW_HASH_TABLE_GC_SIZE, FLOW_HASH_TABLE_GC_PERIOD, FLOW_HASH_TABLE_GC_TIMEOUT);

	fp_stats = fopen(stat_file_name, "w+");
	Stats s = stats_snapshot();
	log_add_fp(fp_stats, LOG_STATS);

	fprintf(fp_stats, "time,level,file,line,msg,%s\n", stats_csv_header_to_string());

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

	LoadInternalNets("/home/zhihaow/codes/honeypot_c_controller/conf/net.internal");
	LoadResponderNets("/home/zhihaow/codes/honeypot_c_controller/conf/net.responder");
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

	char *recv_intf = argv[1];

	printf("Capturing on the device: %s\n", recv_intf);

	/* Capture the Ctrl+C single */
	signal(SIGINT, sig_proc);

	/* open the device for sniffing. Here we use create+activate rather to avoid the packet buffer in libpcap. */
	// pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	pcap = pcap_create(recv_intf, errbuf);

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
		fprintf(stderr, "Couldn't open device %s: %s\n", recv_intf, errbuf);
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

	/* make sure every data structure is in place */
	trace_check();

	ret = pread_tcpdump(&current_time, &len, &tlen, &phys, &phystype, &pip,
						&plast);
	last_lazy_free_log_time = last_hash_cleaned_time = last_idle_cleaned_time = last_pkt_cleaned_time = last_log_time = current_time;

#ifdef HOST_LIVENESS_MONITOR
	base_ip_int = ip_to_int("154.200.0.0");
	last_active_entry_update_time = last_active_host_merge_time = current_time;
#endif
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

#ifdef FLOW_HASH_MEASURE
			flow_hash_stats_cal();
#endif

			Stats s = stats_snapshot();
			log_stats("stats,%s", stats_to_csv_string(&s));

#ifdef FLOW_HASH_MEASURE
			flow_hash_stats_init();
#endif
		}
		if (pkt_count % 100000 == 0)
		{
			print_all_stats();
		}
#ifdef PKT_PROCESS_TIME_MEASURE
		if (pkt_count % PKT_LOG_SAMPLE_CNT == 0)
		{
			gettimeofday(&pkt_process_end_time, NULL);
			log_stats("pkt_processing_time,%ld,%d", pkt_count, tv_sub_2(pkt_process_end_time, current_time));
		}
#endif
#endif

#ifdef HOST_LIVENESS_MONITOR
		// Merge the two bitmap of host liveness
		if (tv_sub_2(current_time, last_active_host_merge_time) >= ACTIVE_HOST_UPDATE_PERIOD)
		{
			last_active_host_merge_time = current_time;
			merge_host_liveness();
			// uint32_t count = count_active_hosts();
			// printf("Active hosts: %d\n", count);
		}
#endif

	} while ((ret = pread_tcpdump(&current_time, &len, &tlen, &phys, &phystype, &pip, &plast)) > 0);

	clean_all();
	return 0;
}
