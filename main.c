#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

/* Test task
 * Using C, write an analogue of tcpdump (console application)
 * which analyzes all packages that meet the specified criteria
 * (like source/ destination MAC, source/ destination IP address, source/destination port),
 *  and keeps the following statistics:
 *	List of all MAC addresses of the packages; quantity of packages sent to/from a specified MAC address.
 *  List of all IP addresses of the packages; quantity of TCP and UDP packages sent.
 *
 * Demand: Possibility of binding to a specified network interface (eth0).
 *
*/

static char *program_name;
static pcap_t *descr_p;

u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char*packet);
u_char* handle_IP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
static void countme(u_char*, const struct pcap_pkthdr*, const u_char*);
static char *copy_argv(register char **argv);
static void usage(void);

int main(int argc, char **argv)
{
	int option;
	char *cp;
	char *cmdbuf;
	char *device;   // device name or NULL if device not specified
	int timeout = 1000;
	bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN; // netmask set to capture on more than one network
	struct bpf_program filter_code;			// hold compiled program
	int status;
	char errbuf[PCAP_ERRBUF_SIZE];
	int packet_count;

	device = NULL;

	if((cp = strrchr(argv[0], '/')) != NULL)
	{
		program_name = cp + 1;
	}
	else
	{
		program_name = argv[0];
	}

	// parse optional arguments
	while ((option = getopt(argc, argv, "i:")) != -1)
	{
		switch (option)
		{
		case 'i':
			device = optarg;
			break;

			/*  here it is possible to set
		 *  another optional arguments
		 *  if it will be needed
		 */

		default:
			usage();
		}
	}

	if (device == NULL)
	{
		device = pcap_lookupdev(errbuf);

		if (device == NULL)
		{
			printf("%s\n", errbuf);
			exit(1);
		}
	}

	// on Linux systems with 2.2 or later kernels,
	// a source argument of "any" or NULL can be used to capture packets from all interfaces
	//device = NULL;

	// create a live capture handle
	descr_p = pcap_create(device, errbuf);

	if (descr_p == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}

	status = pcap_set_timeout(descr_p, timeout);

	// activate a capture handle
	status = pcap_activate(descr_p);

	if (status < 0)
	{
		// pcap_activate() failed.
		printf("%s: %s\n(%s)", device, pcap_statustostr(status), pcap_geterr(descr_p));
		exit(1);
	}
	else if (status > 0)
	{
		// pcap_activate() succeeded, but it's warning
		printf("%s: %s\n(%s)", device, pcap_statustostr(status), pcap_geterr(descr_p));
	}

	// cmdbuf - expression bufer
	// optind - index of the next elem of argv
	cmdbuf = copy_argv(&argv[optind]);

	if (pcap_compile(descr_p, &filter_code, cmdbuf, 1, netmask) < 0)
	{
		printf("%s", pcap_geterr(descr_p));
		exit(1);
	}

	if (pcap_setfilter(descr_p, &filter_code) < 0)
	{
		printf("%s", pcap_geterr(descr_p));
		exit(1);
	}

	if(device != NULL)
	{
		printf("Listening on %s interface\n", device);
	}

	while(1)
	{
		packet_count = 0;
		status = pcap_dispatch(descr_p, -1, countme, (u_char *)&packet_count);

		if (status < 0)
			break;

		if (status != 0)
		{
			printf("%d packet(s)\n", packet_count);
		}
	}

	(void)fflush(stdout);

	if (status == -1)
	{
		// error report
		(void)fprintf(stderr, "%s: pcap_loop: %s\n", program_name, pcap_geterr(descr_p));
	}

	pcap_close(descr_p);

	exit(status == -1 ? 1 : 0);
}



/* callback function that is passed to pcap_dispatch(...) and called each time
 * a packet is recieved
 */
static void countme(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	int *counterp = (int *)args;

	if(*counterp == 0)
	{
		u_int16_t type = handle_ethernet(args, pkthdr, packet);

		if(type == ETHERTYPE_IP)
		{
			/* handle IP packet */
			handle_IP(args, pkthdr, packet);
		}
	}

	(*counterp)++;
}


/* Function copied from libpcap/test code
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 */
static char *copy_argv(register char **argv)
{
	register char **p;
	register u_int len = 0;
	char *buf;
	char *src, *dst;

	p = argv;
	if (*p == 0)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);

	if (buf == NULL)
	{
		printf("copy_argv: malloc");
		exit(1);
	}

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL)
	{
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}

	dst[-1] = '\0';

	return buf;
}

u_int16_t handle_ethernet (u_char *args, const struct pcap_pkthdr* pkthdr, const u_char*packet)
{
	struct ether_header *eptr;  /* net/ethernet.h */

	/* lets start with the ether header... */
	eptr = (struct ether_header *) packet;

	/* check to see if we have an ip packet */
	if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
	{
		fprintf(stdout,"MAC: %s", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));

		fprintf(stdout," > %s ", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

		fprintf(stdout,"(IP)");
	}

	fprintf(stdout, ", ");

	return ntohs (eptr->ether_type);
}


/*
 * Structure of an internet header
 * Stolen from tcpdump source
 */
struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};


u_char* handle_IP(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	const struct my_ip* ip;
	u_int length = pkthdr->len;
	u_int off;

	/* jump pass the ethernet header */
	ip = (struct my_ip*)(packet + sizeof(struct ether_header));
	length -= sizeof(struct ether_header);

	/* Check to see if we have the first fragment */
	off = ntohs(ip->ip_off);

	if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
	{
		/* print SOURCE DESTINATION hlen version len offset */
		fprintf(stdout,"IP: ");
		fprintf(stdout,"%s > ", inet_ntoa(ip->ip_src));
		fprintf(stdout,"%s ", inet_ntoa(ip->ip_dst));

		/* determine protocol */
		switch(ip->ip_p)
		{
		case IPPROTO_TCP:
			printf("(TCP) ");
			break;
		case IPPROTO_UDP:
			printf("(UDP) ");
			return NULL;
		default:
			printf("(unknown) ");
			return NULL;
		}
	}

	return NULL;
}


static void usage(void)
{
	fprintf(stderr, "Usage: %s [ -i interface ] [expression]\n"
					"Expression: read man here http://www.tcpdump.org/manpages/pcap-filter.7.html .\n", program_name);
	exit(1);
}
