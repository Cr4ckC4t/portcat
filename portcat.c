/*

   +---------------------------------------------+
   | <PORTCAT>                                   |
   |                                             |
   | A small and very basic TCP SYN port scanner |
   | for quick reconnaissance and learning basic |
   | linux socket programming in C.              |
   |                                             |
   +---------------------------------@crackcat---+

   [Compile with]
   gcc -pthread -Wall -Wpedantic -o portcat portcat.c

   [Disclaimer]
   It's a dumb tool but it was fun writing.

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#define RECV_TIMEOUT_S 2

// Format colors
#define FC_END      "\033[0m"
#define FC_BLACK    "\033[0;30m"
#define FC_RED      "\033[0;31m"
#define FC_GREEN    "\033[0;32m"
#define FC_YELLOW   "\033[0;33m"
#define FC_BLUE     "\033[0;34m"
#define FC_PURPLE   "\033[0;35m"
#define FC_CYAN     "\033[0;36m"

void* receive_ack(void* ptr);
void process_packet(unsigned char* buffer, int size);
int start_recv(void);
int get_local_ip(char* buffer, struct in_addr dest);
char* hostname_to_ip(char* hostname);
unsigned short csum(unsigned short* ptr, int nbytes);

void display_banner(void);
void print_port_list(void);
void suggestions(char* target);

struct pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};

struct in_addr dest_ip;
int open_ports[65536];

int main(int argc, char** argv) {

	if (argc != 2) {
		fprintf(stderr, "%s[!]%s Argument error. Usage: %s <hostname|ip>\n", FC_RED, FC_END, argv[0]);
		exit(EXIT_FAILURE);
	}

	display_banner();

	char* target = argv[1];

	if (inet_addr(target) != -1) {
		dest_ip.s_addr = inet_addr(target);
	} else {
		const char* ip = hostname_to_ip(target);
		if (ip != NULL) {
			dest_ip.s_addr = inet_addr(ip);
		} else {
			fprintf(stderr, "%s[!]%s Unable to resolve hostname: %s\n", FC_RED, FC_END, target);
			exit(EXIT_FAILURE);
		}
	}

	// Create a raw socket
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0) {
		fprintf(stderr, "%s[!]%s Error creating socket. Error code [%s%d%s]: %s\n", FC_RED, FC_END, FC_RED, errno, FC_END, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// TCP datagram
	char datagram[4096];
	memset(datagram, 0, 4096);

	// IP header
	struct iphdr* iph = (struct iphdr*)datagram;

	// TCP header
	struct tcphdr* tcph = (struct tcphdr*)(datagram+sizeof(struct ip));

	struct sockaddr_in dest;
	struct pseudo_header psh;

	int source_port = 64982;
	char source_ip[20];

	// Get the local IP on the right interface
	int err = get_local_ip(source_ip, dest_ip);
	if (err < 0) {
		fprintf(stderr, "%s[!]%s Error getting local ip. Error code [%s%d%s]: %s\n", FC_RED, FC_END, FC_RED, errno, FC_END, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Fill the IP header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->id = htons(24541);
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(source_ip);
	iph->daddr = dest_ip.s_addr;

	iph->check = csum((unsigned short*)datagram, iph->tot_len >> 1);

	// Fill the TCP header
	tcph->source = htons(source_port);
	tcph->dest = htons(80);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr)/4;
	/*
	*  SYN scan: 0 1 0 0 0 0
	* XMAS scan: 1 0 0 1 0 1
	*/
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(14600);
	tcph->check = 0; // filled by the kernel's IP stack
	tcph->urg_ptr = 0;

	int one = 1;
	const int* val = &one;

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		fprintf(stderr, "%s[!]%s Error setting socket option. Error code [%s%d%s]: %s\n", FC_RED, FC_END, FC_RED, errno, FC_END, strerror(errno));
		exit(EXIT_FAILURE);
	}

	char *message1 = "Listener";
	pthread_t recv_thread;

	if (pthread_create(&recv_thread, NULL, receive_ack, (void*) message1) < 0) {
		fprintf(stderr, "%s[!]%s Error creating thread. Error code [%s%d%s]: %s\n", FC_RED, FC_END, FC_RED, errno, FC_END, strerror(errno));
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "%s[+]%s Starting TCP SYN scan...\n", FC_GREEN, FC_END);
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;

	for (int port=1; port < 65536; port++) {
		tcph->dest = htons(port);
		tcph->check = 0;

		psh.source_address = inet_addr(source_ip);
		psh.dest_address = dest.sin_addr.s_addr;
		psh.placeholder = 0;
		psh.protocol = IPPROTO_TCP;
		psh.tcp_length = htons(sizeof(struct tcphdr));

		memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

		tcph->check = csum((unsigned short*)&psh, sizeof(struct pseudo_header));

		// Send the packet
		if (sendto(sock, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
			fprintf(stderr, "%s[!]%s Error sending SYN packet. Error code [%s%d%s]: %s\n", FC_RED, FC_END, FC_RED, errno, FC_END, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	pthread_join(recv_thread, NULL);
	fprintf(stderr, "\n%s[+]%s Scan done\n", FC_GREEN, FC_END);

	suggestions(target);

	return EXIT_SUCCESS;
}


void* receive_ack(void* ptr) {
	start_recv();
	return NULL;
}


int start_recv(void) {

	int sock_raw;

	socklen_t saddr_size;
	int data_size;
	struct sockaddr saddr;

	unsigned char *buffer = (unsigned char*)malloc(65536);

	sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	if (sock_raw < 0) {
		fprintf(stderr, "%s[!]%s Socket error!\n", FC_RED, FC_END);
		fflush(stderr);
		return EXIT_FAILURE;
	}


	struct timeval tv;
	tv.tv_sec = RECV_TIMEOUT_S;
	tv.tv_usec = 0;
	if (setsockopt(sock_raw, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
		fprintf(stderr, "%s[!]%s Error setting socket option. Error code [%s%d%s]: %s\n", FC_RED, FC_END, FC_RED, errno, FC_END, strerror(errno));
		fflush(stderr);
		return(EXIT_FAILURE);
	}

	saddr_size = sizeof(saddr);

	while (1) {
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);

		// Check whether a timeout ocurred
		if (errno == EAGAIN || errno == EWOULDBLOCK ){
			break;
		}

		if (data_size < 0) {
			fprintf(stderr, "%s[!]%s Error receiving packets!\n", FC_RED, FC_END);
			fflush(stderr);
			return EXIT_FAILURE;
		}

		process_packet(buffer, data_size);
	}

	close(sock_raw);
	return EXIT_SUCCESS;
}


void process_packet(unsigned char* buffer, int size) {
	struct iphdr *iph = (struct iphdr*)buffer;
	struct sockaddr_in source;
	struct sockaddr_in dest;
	unsigned short iphdrlen;

	if (iph->protocol == 6) {
		struct iphdr *iph = (struct iphdr*)buffer;
		iphdrlen = iph->ihl * 4;

		struct tcphdr* tcph = (struct tcphdr*)(buffer + iphdrlen);
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;

		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;

		uint16_t s_port = ntohs(tcph->source);
		if (!open_ports[s_port] && tcph->syn && tcph->ack && source.sin_addr.s_addr == dest_ip.s_addr) {
			fprintf(stdout, "\t%s[~]%s Port: %s%5d%s | open\n", FC_YELLOW, FC_END, FC_GREEN, s_port, FC_END);
			fflush(stdout);
			open_ports[s_port] = 1;
		}
	}
}


int get_local_ip(char* buffer, struct in_addr dest) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		return -1;
	}

	int dns_port = 53;
	struct sockaddr_in serv;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = dest.s_addr;
	serv.sin_port = htons(dns_port);

	// Connect
	int err = connect(sock ,(const struct sockaddr*)&serv, sizeof(serv));
	if (err < 0) {
		return -1;
	}

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*)&name, &namelen);
	if (err < 0) {
		return -1;
	}

	close(sock);

	if (inet_ntop(AF_INET, &name.sin_addr, buffer, 100) == NULL) {
		return -1;
	}
	return 0;
}

char* hostname_to_ip(char* hostname) {
	struct hostent *he;
	struct in_addr **addr_list;

	if ((he = gethostbyname(hostname)) == NULL) {
		herror("gethostbyname");
		return NULL;
	}

	addr_list = (struct in_addr **)he->h_addr_list;

	for (int i=0; addr_list[i] != NULL; i++){
		return inet_ntoa(*addr_list[i]);
	}

	return NULL;
}

unsigned short csum(unsigned short* ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return answer;
}

void display_banner(void) {

	fprintf(stderr, "\n"
"\t %s+----------------------------------+\n"
"\t |%s ___   __  ___  ___  ___  __  ___ %s|\n"
"\t |%s |__) |  | |__)  |  /    |__|  |  %s|\n"
"\t |%s |    |__| |  \\  |  \\___ |  |  |  %s|\n"
"\t |%s                       @crackcat  %s|\n"
"\t +----------------------------------+%s\n"
"\n",
	FC_BLUE, FC_CYAN, FC_BLUE, FC_CYAN, FC_BLUE, FC_CYAN, FC_BLUE, FC_CYAN, FC_BLUE, FC_END);
}


void print_port_list(void) {
	int first=1;
	for (int p=1; p < 65536;p++) {
		if (open_ports[p]) {
			fprintf(stderr,"%s%d",first?"":",",p);
			first = 0;
		}
	}
	if (first) {
		fprintf(stderr, "-");
	}
}

void suggestions(char* target) {

	fprintf(stderr, "%s[+]%s Showing first (port-number-based) suggestions\n", FC_GREEN, FC_END);
	// next default enumeration
	fprintf(stderr, "\t%s[~]%s basic enumeration%s\n", FC_PURPLE, FC_YELLOW, FC_END);
	fprintf(stderr, "\t\t%s#%s nmap -Pn -sS -sV %s -p", FC_RED, FC_END, target);
	print_port_list();
	fprintf(stderr, "\n"
			"\t\t%s#%s nmap -sX %s -p-\n"
			"\t\t%s#%s nmap -sU %s\n"
			"\t\t%s$%s netcat %s <port>\n"
			"\t\t%s$%s enum4linux -a %s\n"
			"\n",
		FC_RED, FC_END, target, FC_RED, FC_END, target, FC_BLUE, FC_END, target, FC_BLUE, FC_END, target
	);

	// ftp
	if (open_ports[21]) {
		fprintf(stderr, "\t%s[~]%s ftp%s (21)%s\n", FC_PURPLE, FC_CYAN, FC_YELLOW, FC_END);
		fprintf(stderr, "\t\t%s$%s ftp %s 21            \n"
				"\t\t|   username: anonymous\n"
				"\t\t|   password: anonymous\n"
				"\n",
			FC_BLUE, FC_END, target
		);
	}
	// ssh
	if (open_ports[22]) {
		fprintf(stderr, "\t%s[~]%s ssh%s (22)%s\n", FC_PURPLE, FC_CYAN, FC_YELLOW, FC_END);
		fprintf(stderr, "\t\t%s$%s hydra -l <user> -P /usr/share/wordlists/rockyou.txt %s -t 4 ssh -v -f\n"
				"\n",
			FC_BLUE, FC_END, target
		);
	}
	// telnet
	if (open_ports[23]) {
		fprintf(stderr, "\t%s[~]%s telnet%s (23)%s\n", FC_PURPLE, FC_CYAN, FC_YELLOW, FC_END);
		fprintf(stderr, "\t\t%s$%s telnet %s 23\n\n", FC_BLUE, FC_END, target);
	}
	// http
	if (open_ports[80]) {
		fprintf(stderr, "\t%s[~]%s http%s (80)%s\n", FC_PURPLE, FC_CYAN, FC_YELLOW, FC_END);
		fprintf(stderr, "\t\t%s$%s gobuster dir -w /usr/share/wordlists/dirb/common.txt -x txt,html,php,bak -u http://%s\n"
				"\t\t%s#%s nmap -sS -sV --script=vuln -p80 %s\n"
				"\t\t%s$%s nikto -h %s\n"
				"\n",
			FC_BLUE, FC_END, target, FC_RED, FC_END, target,FC_BLUE, FC_END, target
		);
	}
	// pop3
	if (open_ports[110]) {
		fprintf(stderr, "\t%s[~]%s pop3%s (110)%s\n", FC_PURPLE, FC_CYAN, FC_YELLOW, FC_END);
		fprintf(stderr, "\t\t$ telnet %s 110\n", target);
	}
	// samba
	if (open_ports[445]) {
		fprintf(stderr, "\t%s[~]%s netbios_ssn%s (445)%s\n", FC_PURPLE, FC_CYAN, FC_YELLOW, FC_END);
		fprintf(stderr, "\t\t%s$%s smbmap -H %s -R\n"
				"\t\t|   %s$%s smbclient \\\\%s\\<disk>\n"
				"\t\t|   %s$%s smbget -R smb://%s/<share>\n"
				"\n",
			FC_BLUE, FC_END, target, FC_BLUE, FC_END, target, FC_BLUE, FC_END, target
		);

	}
	// file shares
	if (open_ports[2049]) {
		fprintf(stderr, "\t%s[~]%s nfs_acl%s (2049)%s\n", FC_PURPLE, FC_CYAN, FC_YELLOW, FC_END);
		fprintf(stderr, "\t\t%s$%s showmount -e %s\n"
				"\t\t|   %s#%s mount %s:/<share> <local-dir>\n"
				"\n",
			FC_BLUE, FC_END, target, FC_RED, FC_END, target
		);
	}
	// docker
	if (open_ports[2375]) {
		fprintf(stderr, "\t%s[~]%s docker%s (2375)%s\n", FC_PURPLE, FC_CYAN, FC_YELLOW, FC_END);
		fprintf(stderr, "\t\t%s$%s docker -H %s images\n"
				"\t\t|   %s$%s docker -h %s:2375 run -v /:/mnt --rm -it <image> chroot /mnt sh\n"
				"\n",
			FC_BLUE, FC_END, target, FC_BLUE, FC_END, target
		);
	}
	// mysql
	if (open_ports[3306]) {
		fprintf(stderr, "\t%s[~]%s mysql%s (3306)%s\n", FC_PURPLE, FC_CYAN, FC_YELLOW, FC_END);
		fprintf(stderr, "\t\t%s$%s mysql -uroot -p -h %s -p 3306\n"
				"\t\t|   password: root | <empty>\n"
				"\n",
			FC_BLUE, FC_END, target
		);
	}
}
