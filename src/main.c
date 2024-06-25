#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include "header.h"

/* looking at ethernet headers */
void my_callback(u_char *args, struct pcap_pkthdr *pkthdr, u_char *packet)
{
	u_int16_t type = handle_ethernet(args, pkthdr, packet);
	u_char ip_proto;

	if (type == ETHERTYPE_IP)
	{ /* handle IP packet */
		ip_proto = handle_IP(args, pkthdr, packet);
		if (ip_proto == IPPROTO_ICMP)
		{
			handle_ICMP(args, pkthdr, packet);
		}
	}
	else if (type == ETHERTYPE_ARP)
	{ /* handle arp packet */
	}
	else if (type == ETHERTYPE_REVARP)
	{ /* handle reverse arp packet */
	}
}

u_char handle_ICMP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	const struct icmp *picmp;
	u_char icmp_type;
	u_char icmp_code;

	picmp = (struct icmp *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
	icmp_type = picmp->icmp_type;
	icmp_code = picmp->icmp_code;
	
	printf("icmp type: %d, icmp_code: %d \n", icmp_type, icmp_code);
	if (icmp_type == ICMP_ECHO) {

	}
	return 0;
}

u_char handle_IP(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	const struct ip *pip;
	u_int length = pkthdr->len;
	u_char ip_proto;
	u_int hlen, off, version;
	int i;
	int len;

	/* jump pass the ethernet header */
	pip = (struct ip *)(packet + sizeof(struct ether_header));
	length -= sizeof(struct ether_header);

	/* check to see we have a packet of valid length */
	if (length < sizeof(struct ip))
	{
		printf("truncated ip %d", length);
		return -1;
	}

	len = ntohs(pip->ip_len);
	hlen = pip->ip_len;	 /* header length */
	version = pip->ip_v; /* ip version */

	/* check version */
	if (version != 4)
	{
		fprintf(stdout, "Unknown version %d\n", version);
		return -1;
	}

	/* check header length */
	if (hlen < 5)
	{
		fprintf(stdout, "bad-hlen %d \n", hlen);
	}

	/* see if we have as much packet as we should */
	if (length < len)
		printf("\ntruncated IP - %d bytes missing\n", len - length);

	ip_proto = pip->ip_p;
	return ip_proto;
}

/* handle ethernet packets, much of this code gleaned from
 * print-ether.c from tcpdump source
 */
u_int16_t handle_ethernet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	u_int caplen = pkthdr->caplen;
	u_int length = pkthdr->len;
	struct ether_header *eptr; /* net/ethernet.h */
	u_short ether_type;

	if (caplen < ETHER_HDRLEN)
	{
		fprintf(stdout, "Packet length less than ethernet header length\n");
		return -1;
	}

	/* lets start with the ether header... */
	eptr = (struct ether_header *)packet;
	ether_type = ntohs(eptr->ether_type);

	/* Lets print SOURCE DEST TYPE LENGTH */
	fprintf(stdout, "ETH: ");
	fprintf(stdout, "%s ", ether_ntoa((struct ether_addr *)eptr->ether_shost));
	fprintf(stdout, "%s ", ether_ntoa((struct ether_addr *)eptr->ether_dhost));

	/* check to see if we have an ip packet */
	if (ether_type == ETHERTYPE_IP)
	{
		fprintf(stdout, "(IP)");
	}
	else if (ether_type == ETHERTYPE_ARP)
	{
		fprintf(stdout, "(ARP)");
	}
	else if (eptr->ether_type == ETHERTYPE_REVARP)
	{
		fprintf(stdout, "(RARP)");
	}
	else
	{
		fprintf(stdout, "(?)");
	}
	fprintf(stdout, " %d\n", length);

	return ether_type;
}

int main(int argc, char *argv[])
{
	pcap_t *descr;				   /* Session handle */
	char *dev;					   /* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
	struct bpf_program fp;		   /* The compiled filter */
	char filter_exp[] = "icmp";	   /* The filter expression */
	struct pcap_pkthdr header; /* The header that pcap gives us */
	struct ether_header *eptr; /* net/ethernet.h */
	u_char *ptr;			   /* printing out hardware header info */
	const u_char *packet;	   /* The actual packet */
	int ret;
	pcap_if_t *all_devs;

	/* Define the device */
	if (pcap_findalldevs(&all_devs, errbuf) == -1)
	{
		fprintf(stderr, "error finding devices");
		return 1;
	}
	dev = all_devs->name;
	// or loop through all_devs to find the one you want
	if (all_devs == NULL)
	{
		printf("Error finding devices: %s\n", errbuf);
		return 1;
	}
	printf("DEV: %s\n", dev);

	/* open the device for sniffing. */
	descr = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (descr == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return (2);
	}

	/* Complile the filter represented by string*/
	if (pcap_compile(descr, &fp, filter_exp, 1, 0) == -1)
	{
		fprintf(stderr, "Error calling pcap_compile\n");
		return (2);
	}

	/* set the compiled program as the filter */
	if (pcap_setfilter(descr, &fp) == -1)
	{
		fprintf(stderr, "Error setting filter\n");
		return (2);
	}

	ret = pcap_loop(descr, -1, my_callback, NULL);

	return 0;
}