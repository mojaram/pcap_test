#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>



#define ETHERTYPE_IP 0x0800



struct libnet_ethernet_hdr

{

    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */

    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */

    u_int16_t ether_type;                 /* protocol */

};



struct libnet_ipv4_hdr

{

    u_int8_t ip_hl:4,       /* version */

           ip_v:4;        /* header length */

    u_int8_t ip_tos;       /* type of service */

    u_int16_t ip_len;         /* total length */

    u_int16_t ip_id;          /* identification */

    u_int16_t ip_off;

    u_int8_t ip_ttl;          /* time to live */

    u_int8_t ip_p;            /* protocol */

    u_int16_t ip_sum;         /* checksum */

    struct in_addr ip_src, ip_dst; /* source and dest address */

};



struct libnet_tcp_hdr

{

    u_int16_t th_sport;       /* source port */

    u_int16_t th_dport;       /* destination port */

    u_int32_t th_seq;          /* sequence number */

    u_int32_t th_ack;          /* acknowledgement number */

    u_int8_t th_off:4,        /* data offset */

           th_x2:4;         /* (unused) */

    u_int8_t  th_flags;       /* control flags */

    u_int16_t th_win;         /* window */

    u_int16_t th_sum;         /* checksum */

    u_int16_t th_urp;         /* urgent pointer */

};



void usage() {

	printf("syntax: pcap_test <interface>\n");

	printf("sample: pcap_test wlan0\n");

}



void print_mac(const u_char* p, u_int8_t *p2) {

	for(int i=0; i<6; i++) {

		printf("%02x", p2[i]);

	}

	printf("\n");

}



void print_ip(const u_char* p, struct in_addr p2) {

	printf("%s\n", inet_ntoa(p2));

}



void print_port(const u_char* p, u_int16_t port) {

	printf("%d\n", port);

}



void print_data(const u_char* p, int data_len, int print_len) {

	for(int i = 0; (i < data_len) && (i < 32); i++) {

		printf("%02x ", p[print_len + i]);

	}

	printf("\n");

}



void dump(const u_char* p, int len){
	struct libnet_ethernet_hdr * hdr;

	hdr = (struct libnet_ethernet_hdr *)p;

	printf("Ethernet Header src mac : 0x");

	print_mac(p, hdr->ether_shost);

	printf("Ethernet Header dst mac : 0x");

	print_mac(p, hdr->ether_dhost);

	if(ntohs(hdr->ether_type) == ETHERTYPE_IP) { // IP
		struct libnet_ipv4_hdr * hdr;
		hdr = (struct libnet_ipv4_hdr *)(p + sizeof(struct libnet_ethernet_hdr));

		printf("IP Header src ip : ");

		print_ip(p, hdr->ip_src);

		printf("IP Header dst ip : ");

		print_ip(p, hdr->ip_dst);

		int IP_tlen = hdr->ip_len;

		int IP_hlen = (hdr->ip_hl) * 4;

		if((hdr->ip_p) == IPPROTO_TCP) { // TCP
			struct libnet_tcp_hdr * hdr;
			hdr = (struct libnet_tcp_hdr *)(p + sizeof(struct libnet_ethernet_hdr) + IP_hlen);

			printf("TCP Header src port : ");

			print_port(p, ntohs(hdr->th_sport));

			printf("TCP Header dst port : ");

			print_port(p, ntohs(hdr->th_dport));

			int TCP_hlen = (hdr->th_off) * 4;

			int data_len = ntohs(IP_tlen) - IP_hlen - TCP_hlen;

			int print_len = 14 + IP_hlen + TCP_hlen;

			printf("Payload(Data) hexa decimal value : 0x");

			print_data(p, data_len, print_len);

		}

	}

	printf("\n");

}



int main(int argc, char* argv[]) {

	if (argc != 2) {

		usage();

		return -1;

	}



	char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {

		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);

		return -1;

	}

	printf("packet capture\n");

	while (true) {

		struct pcap_pkthdr* header;

		const u_char* packet;

		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;

		if (res == -1 || res == -2) break;

		// printf("%u bytes captured\n", header->caplen);

		dump(packet, header->caplen);

	}



	pcap_close(handle);

	return 0;

}