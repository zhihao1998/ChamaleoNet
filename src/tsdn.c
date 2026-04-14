#include "tsdn.h"
#include "stats_print.h"
#include <errno.h>
#include <inttypes.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <sys/stat.h>
#include <time.h>

#define TSDN_REPO_ROOT "/home/zhihaow/codes/honeypot_c_controller"

static char g_capture_ifname[64];
static char g_tsdn_run_dir[512];

static int mkdir_p(const char *path, mode_t mode)
{
	char buf[512];
	char *p;
	size_t n;

	n = snprintf(buf, sizeof(buf), "%s", path);
	if (n >= sizeof(buf))
		return -1;

	for (p = buf + 1; *p; p++)
	{
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(buf, mode) != 0 && errno != EEXIST)
			return -1;
		*p = '/';
	}
	if (mkdir(buf, mode) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

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

	controller_rule_install_count = 0;
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

/*
 * Linux AF_PACKET + TPACKET/mmap: pcap_stats() often leaves ps_recv/ps_drop at0.
 * PACKET_STATISTICS returns deltas since the previous getsockopt and clears them;
 * we accumulate into these totals for display and pcap_pend.
 */
static uint64_t g_sock_rx_total;
static uint64_t g_sock_drop_total;

static void refresh_linux_sock_stats(void)
{
#ifdef __linux__
	int fd;
	struct tpacket_stats_v3 st3;
	struct tpacket_stats st;
	socklen_t len;

	if (pcap == NULL)
		return;
	fd = pcap_fileno(pcap);
	if (fd < 0)
		return;

	len = sizeof(st3);
	if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &st3, &len) == 0)
	{
		g_sock_rx_total += (uint64_t)st3.tp_packets;
		g_sock_drop_total += (uint64_t)st3.tp_drops;
		return;
	}
	len = sizeof(st);
	if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &st, &len) == 0)
	{
		g_sock_rx_total += (uint64_t)st.tp_packets;
		g_sock_drop_total += (uint64_t)st.tp_drops;
	}
#endif
}

/* Prefer pcap_stats when ps_recv > 0; else use accumulated PACKET_STATISTICS.
 * Returns 1 if recv/drop were taken from PACKET_STATISTICS fallback. */
static int merge_pcap_rx_display(uint64_t *pr, uint64_t *pd, uint64_t *pif)
{
	struct pcap_stat st;
	int ok = (pcap != NULL && pcap_stats(pcap, &st) == 0);
	int used_sock = 0;

	refresh_linux_sock_stats();

	*pr = 0;
	*pd = 0;
	*pif = 0;
	if (ok)
	{
		*pr = (uint64_t)st.ps_recv;
		*pd = (uint64_t)st.ps_drop;
		*pif = (uint64_t)st.ps_ifdrop;
	}

	/*
	 * On Linux mmap capture, libpcap and PACKET_STATISTICS may diverge
	 * per field. Use the larger accumulated value for recv/drop so we
	 * don't hide kernel-reported drops when pcap_stats keeps drop at 0.
	 */
	if (g_sock_rx_total > *pr)
	{
		*pr = g_sock_rx_total;
		used_sock = 1;
	}
	if (g_sock_drop_total > *pd)
	{
		*pd = g_sock_drop_total;
		used_sock = 1;
	}
	return used_sock;
}

struct in_addr *internal_net_list;
int *internal_net_mask;
int tot_internal_nets;

struct in_addr *responder_net_list;
int *responder_net_mask;
int tot_responder_nets;

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
		if (SendPktCollector((char *)peth, tlen) == -1)
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

/* ethtool stat index: -2 = not resolved, -1 = none, else data[] index */
static int g_ethtool_oob_idx = -2;
static uint64_t g_prev_rx_packets;
static uint64_t g_prev_oob;
static int g_stat_delta_inited;

static int read_sysfs_u64_path(const char *path, uint64_t *out)
{
	FILE *fp;

	fp = fopen(path, "r");
	if (!fp)
		return -1;
	if (fscanf(fp, "%" SCNu64, out) != 1)
	{
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

/*
 * Driver counter often related to NIC/host buffer exhaustion (e.g. mlx5
 * rx_out_of_buffer). Cumulative; we print delta since last sample. Returns0
 * and *val, or -1 if unavailable.
 */
static int ethtool_oob_stat(const char *ifname, uint64_t *val)
{
	int fd, ret = -1;
	struct ifreq ifr;
	struct ethtool_drvinfo drv = {.cmd = ETHTOOL_GDRVINFO};
	struct ethtool_gstrings *gs;
	struct ethtool_stats *es;
	uint32_t n_stats, i;
	size_t glen, slen;

	*val = 0;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ifr.ifr_data = (void *)&drv;
	if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
		goto out_fd;
	n_stats = drv.n_stats;
	if (n_stats == 0 || n_stats > 8192U)
		goto out_fd;

	glen = sizeof(struct ethtool_gstrings) + (size_t)n_stats * ETH_GSTRING_LEN;
	slen = sizeof(struct ethtool_stats) + (size_t)n_stats * sizeof(uint64_t);
	gs = (struct ethtool_gstrings *)calloc(1, glen);
	es = (struct ethtool_stats *)calloc(1, slen);
	if (!gs || !es)
		goto out_alloc;

	gs->cmd = ETHTOOL_GSTRINGS;
	gs->string_set = ETH_SS_STATS;
	gs->len = n_stats;
	ifr.ifr_data = (void *)gs;
	if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
		goto out_alloc;

	if (g_ethtool_oob_idx == -2)
	{
		g_ethtool_oob_idx = -1;
		for (i = 0; i < n_stats; i++)
		{
			char *s = (char *)&gs->data[i * ETH_GSTRING_LEN];

			s[ETH_GSTRING_LEN - 1] = '\0';
			if (strstr(s, "out_of_buffer") || strstr(s, "out_of_buff") ||
			    strstr(s, "rx_no_buffer") ||
			    strstr(s, "rx_buf_alloc_fail") ||
			    strstr(s, "rx_alloc_fail") ||
			    strstr(s, "no_dma_resources"))
			{
				g_ethtool_oob_idx = (int)i;
				break;
			}
		}
	}

	es->cmd = ETHTOOL_GSTATS;
	es->n_stats = n_stats;
	ifr.ifr_data = (void *)es;
	if (ioctl(fd, SIOCETHTOOL, &ifr) < 0)
		goto out_alloc;

	if (g_ethtool_oob_idx >= 0 && (uint32_t)g_ethtool_oob_idx < n_stats)
	{
		*val = es->data[g_ethtool_oob_idx];
		ret = 0;
	}

out_alloc:
	free(gs);
	free(es);
out_fd:
	close(fd);
	return ret;
}

/*
 * pcap_pend: libpcap ps_recv minus pkt_count (accounting gap: pcap-delivered vs
 *   packets processed in the main loop; not the same as NIC sysfs counters).
 * bloom_rsp: S2C responses that entered the bloom / switch-send path (flows
 *   that need bloom-side handling; see bloom_rule_sending_count_tot).
 * nic_drx: delta of /sys/.../statistics/rx_packets since last sample (host
 *   stack view of packets received on this interface).
 * nic_oob_d: delta of driver ethtool “out of buffer”-style stat when present
 *   (NIC/driver buffer pressure; not the same as pcap_pend).
 *
 * TTY: fixed header, only the value line is redrawn. Logs / .status: one line.
 */
static void tsdn_emit_status_line(void)
{
	static int status_tty_hdr_done;
	uint64_t pr = 0, pd = 0, pif = 0;
	int64_t pcap_pend;
	uint64_t pkt_pps = 0;
	uint64_t nic_pps = 0;
	static struct timespec prev_pps_ts;
	static uint64_t prev_pps_pkt;
	static int pps_inited;
	uint32_t ruleq = rule_queue_depth();
	char sysfs_rx[256];
	uint64_t rx_packets = 0, oob_now = 0, nic_drx = 0, nic_oob_d = 0;
	int have_rx, have_oob;
	int tty = isatty(fileno(stderr));
	struct timespec pps_now;
	double sample_dt = 0.0;

	(void)merge_pcap_rx_display(&pr, &pd, &pif);
	pcap_pend = (int64_t)pr - (int64_t)pkt_count;

	clock_gettime(CLOCK_MONOTONIC, &pps_now);
	if (pps_inited)
	{
		sample_dt = (pps_now.tv_sec - prev_pps_ts.tv_sec) +
			    (pps_now.tv_nsec - prev_pps_ts.tv_nsec) / 1e9;

		if (sample_dt >= 1e-3 && pkt_count >= prev_pps_pkt)
			pkt_pps = (uint64_t)((double)(pkt_count - prev_pps_pkt) / sample_dt + 0.5);
	}
	prev_pps_ts = pps_now;
	prev_pps_pkt = pkt_count;
	pps_inited = 1;

	snprintf(sysfs_rx, sizeof(sysfs_rx), "/sys/class/net/%s/statistics/rx_packets",
		 g_capture_ifname);
	have_rx = (read_sysfs_u64_path(sysfs_rx, &rx_packets) == 0);
	have_oob = (ethtool_oob_stat(g_capture_ifname, &oob_now) == 0);

	if (!g_stat_delta_inited)
	{
		if (have_rx)
			g_prev_rx_packets = rx_packets;
		if (have_oob)
			g_prev_oob = oob_now;
		g_stat_delta_inited = 1;
		nic_drx = 0;
		nic_oob_d = 0;
	}
	else
	{
		if (have_rx)
		{
			nic_drx = rx_packets - g_prev_rx_packets;
			if (pps_inited && sample_dt >= 1e-3)
				nic_pps = (uint64_t)((double)nic_drx / sample_dt + 0.5);
			g_prev_rx_packets = rx_packets;
		}
		else
		{
			nic_drx = 0;
			nic_pps = 0;
		}

		if (have_oob)
		{
			nic_oob_d = oob_now - g_prev_oob;
			g_prev_oob = oob_now;
		}
		else
		{
			nic_oob_d = 0;
		}
	}

	if (tty)
	{
		if (!status_tty_hdr_done)
		{
			fprintf(stderr,
				"%-10s %8s %8s %10s %8s %8s %6s %8s %10s %8s %8s %10s %10s %10s %5s\n",
				"IFACE", "pkt_pps", "nic_pps", "pkt", "buf", "flow", "exp",
				"bloom_rsp", "pcap_rx", "pcap_drp", "pcap_ifdr",
				"pcap_pend", "nic_drx", "nic_oob_d", "ruleq");
			fflush(stderr);
			status_tty_hdr_done = 1;
		}
		else
			fprintf(stderr, "\033[1A\033[2K\r");
		fprintf(stderr,
			"%-10s %8" PRIu64 " %8" PRIu64 " %10" PRIu64 " %8" PRIu64 " %8" PRIu64 " %6" PRIu64
			" %8" PRIu64 " %10" PRIu64 " %8" PRIu64 " %8" PRIu64 " %10" PRId64
			" %10" PRIu64,
			g_capture_ifname, pkt_pps, nic_pps, pkt_count, pkt_buf_count, flow_hash_count,
			expired_pkt_count_tot, bloom_rule_sending_count_tot, pr, pd, pif,
			pcap_pend, nic_drx);
		if (have_oob)
			fprintf(stderr, " %10" PRIu64, nic_oob_d);
		else
			fprintf(stderr, " %10s", "-");
		fprintf(stderr, " %5u\n", ruleq);
		fflush(stderr);
	}
	else
	{
		fprintf(stderr,
			"[%s] pkt_pps=%" PRIu64 " nic_pps=%" PRIu64 " pkt=%" PRIu64 " buf=%" PRIu64 " flow=%" PRIu64
			" expired=%" PRIu64 " bloom_rsp=%" PRIu64
			" pcap_recv=%" PRIu64 " pcap_drop=%" PRIu64 " pcap_ifdrop=%" PRIu64
			" pcap_pend=%" PRId64 " nic_drx=%" PRIu64 " ",
			g_capture_ifname, pkt_pps, nic_pps, pkt_count, pkt_buf_count, flow_hash_count,
			expired_pkt_count_tot, bloom_rule_sending_count_tot, pr, pd, pif,
			pcap_pend, nic_drx);
		if (have_oob)
			fprintf(stderr, "nic_oob_d=%" PRIu64 " ", nic_oob_d);
		else
			fprintf(stderr, "nic_oob_d=- ");
		fprintf(stderr, "ruleq=%u\n", ruleq);
	}

	if (g_tsdn_run_dir[0] != '\0')
	{
		char path[640];
		FILE *fp;

		snprintf(path, sizeof(path), "%s/tsdn/%s.status", g_tsdn_run_dir,
			 g_capture_ifname);
		fp = fopen(path, "w");
		if (fp)
		{
			fprintf(fp,
				"%-10s %8" PRIu64 " %8" PRIu64 " %10" PRIu64 " %8" PRIu64 " %8" PRIu64
				" %6" PRIu64 " %8" PRIu64 " %10" PRIu64 " %8" PRIu64 " %8" PRIu64
				" %10" PRId64 " %10" PRIu64,
				g_capture_ifname, pkt_pps, nic_pps, pkt_count, pkt_buf_count,
				flow_hash_count, expired_pkt_count_tot,
				bloom_rule_sending_count_tot, pr, pd, pif, pcap_pend,
				nic_drx);
			if (have_oob)
				fprintf(fp, " %10" PRIu64, nic_oob_d);
			else
				fprintf(fp, " %10s", "-");
			fprintf(fp, " %5u\n", ruleq);
			fclose(fp);
		}
	}
}

void print_all_stats()
{
	Stats s = stats_snapshot();
	uint64_t pr, pd, pif;
	int sock_fb;

	stats_print(stdout, &s, STATS_FMT_KV, 0);

	sock_fb = merge_pcap_rx_display(&pr, &pd, &pif);
	printf("\n%ld.%ld Pcap statistics (recv/drop: %s)\n", current_time.tv_sec,
	       current_time.tv_usec,
	       sock_fb ? "Linux PACKET_STATISTICS (pcap_stats recv was 0)"
			: "libpcap pcap_stats");
	printf("Received: %" PRIu64 ", Processed: %" PRIu64 ", Still in queue: %" PRId64 ", Dropped: %" PRIu64 ", Dropped by interface: %" PRIu64 "\n",
	       pr, pkt_count, (int64_t)pr - (int64_t)pkt_count, pd, pif);
}

void clean_all()
{
	/* free all data structure */
	trace_cleanup();
	/* close pcap */
	pcap_close(pcap);
	/* close bfrt_grpc */
	entry_install_thread_stop();
	/* close log */
#ifdef LOG_TO_FILE
	// fclose(fp_log);
	fclose(fp_stats);
#endif
}

static volatile sig_atomic_t g_stop = 0;

void sig_proc(int sig)
{
	(void)sig;
	g_stop = 1;
	if (pcap != NULL)
		pcap_breakloop(pcap);
}
void init_log(const char *capture_ifname)
{
	const char *ifname =
	    (capture_ifname && capture_ifname[0]) ? capture_ifname : "unknown";
	snprintf(g_capture_ifname, sizeof(g_capture_ifname), "%s", ifname);

	struct timeval tv;
	gettimeofday(&tv, NULL);
	struct tm *tm = localtime(&tv.tv_sec);

	char log_date[64];
	snprintf(log_date, sizeof(log_date), "%d%02d%02d_%02d-%02d-%02d",
		 tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
		 tm->tm_min, tm->tm_sec);

	char run_dir[512];
	const char *env_run = getenv("TSDN_LOG_RUN_DIR");
	if (env_run != NULL && env_run[0] != '\0')
	{
		snprintf(run_dir, sizeof(run_dir), "%s", env_run);
	}
	else
	{
		snprintf(run_dir, sizeof(run_dir), "%s/log/runs/%s", TSDN_REPO_ROOT,
			 log_date);
	}

	snprintf(g_tsdn_run_dir, sizeof(g_tsdn_run_dir), "%s", run_dir);
	{
		char sub[576];
		snprintf(sub, sizeof(sub), "%s/tsdn", run_dir);
		if (mkdir_p(sub, 0755) != 0)
		{
			fprintf(stderr, "init_log: warning: cannot mkdir %s: %s\n", sub,
				strerror(errno));
		}
	}

	char log_file_name[300], stat_file_name[768], param_file_name[300];
	(void)log_file_name;
	(void)param_file_name;

#ifdef LOG_TO_FILE
	if (mkdir_p(run_dir, 0755) != 0)
	{
		fprintf(stderr, "init_log: cannot create directory %s: %s\n", run_dir,
			strerror(errno));
		exit(1);
	}

	/* One file per process; run_dir is usually log/runs/<timestamp>/ (shared via TSDN_LOG_RUN_DIR for multi-tsdn). */
	snprintf(stat_file_name, sizeof(stat_file_name),
		 "%s/%s_pid%ld_HashSize%d_GCSize%d_GCPeriod%d_GCTimeout%d.csv",
		 run_dir, ifname, (long)getpid(), FLOW_HASH_TABLE_SIZE,
		 FLOW_HASH_TABLE_GC_SIZE, FLOW_HASH_TABLE_GC_PERIOD,
		 FLOW_HASH_TABLE_GC_TIMEOUT);

	fp_stats = fopen(stat_file_name, "w+");
	if (!fp_stats)
	{
		fprintf(stderr, "init_log: cannot open %s: %s\n", stat_file_name,
			strerror(errno));
		exit(1);
	}
	fprintf(stderr, "stats csv: %s\n", stat_file_name);
	log_add_fp(fp_stats, LOG_STATS);

	fprintf(fp_stats, "time,level,file,line,msg,%s\n",
		stats_csv_header_to_string());

#endif
	log_set_quiet(TRUE);
}

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		fprintf(stderr, "usage: %s <capture_interface>\n", argv[0]);
		return 1;
	}
	char *recv_intf = argv[1];

	InitGlobalArrays();
	/* parse the flags */
	// CheckArguments(&argc, argv);

	/* initialize  */
	trace_init();
	init_log(recv_intf);

	if (!LoadInternalNets(
		"/home/zhihaow/codes/honeypot_c_controller/conf/net.internal"))
	{
		fprintf(stderr, "error: loading conf/net.internal failed\n");
		return 1;
	}
	if (!LoadResponderNets(
		"/home/zhihaow/codes/honeypot_c_controller/conf/net.responder"))
	{
		fprintf(stderr, "error: loading conf/net.responder failed\n");
		return 1;
	}
	fprintf(stderr,
		"net config: %d internal prefix(es), %d responder prefix(es) "
		"(responder src|dst hits bypass flow state and go to collector)\n",
		tot_internal_nets, tot_responder_nets);
	// LoadGlobals("conf/globals.conf");

	char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
	struct bpf_program fp;		   /* The compiled filter */
	char filter_exp[] = "ip and not (host 0.0.0.0 or host 255.255.255.255)";
	struct pcap_pkthdr header; /* The header that pcap gives us */
	struct ether_header *eptr; /* net/ethernet.h */
	uint8_t  *ptr;			   /* printing out hardware header info */
	const uint8_t  *packet;	   /* The actual packet */

	int ret = 0;
	int loop_ret = 0;
	struct ip *pip;
	int phystype;
	struct ether_header *phys; /* physical transport header */
	int fix;
	int len;
	int tlen;
	void *plast;
	long int location = 0;
	printf("Capturing on the device: %s\n", recv_intf);

	/* Graceful stop: let main loop exit and print final stats once. */
	signal(SIGINT, sig_proc);
	signal(SIGTERM, sig_proc);
	signal(SIGQUIT, sig_proc);

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

#ifdef FLOW_HASH_MEASURE
			flow_hash_stats_cal();
#endif

			Stats s = stats_snapshot();
			log_stats("stats,%s", stats_to_csv_string(&s));
			tsdn_emit_status_line();

#ifdef FLOW_HASH_MEASURE
			flow_hash_stats_init();
#endif
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

	} while (!g_stop &&
		 (loop_ret = pread_tcpdump(&current_time, &len, &tlen, &phys, &phystype, &pip, &plast)) > 0);

	ret = loop_ret;

	if (ret < 0)
		fprintf(stderr, "capture loop exited on pcap error, printing final stats\n");
	else if (g_stop)
		fprintf(stderr, "capture loop stopped by signal, printing final stats\n");
	else
		fprintf(stderr, "capture loop ended, printing final stats\n");

	{
		Stats s = stats_snapshot();
		log_stats("stats,%s", stats_to_csv_string(&s));
	}
	print_all_stats();
	clean_all();
	return (ret < 0) ? 1 : 0;
}
