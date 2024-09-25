#ifndef MAIN_H
#define MAIN_H

#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct IpHdr {
    uint8_t version;
    uint8_t typeofservice;
    uint16_t total_len;
    uint8_t id;
    uint16_t frag_off;
    uint8_t livetime;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t s_addr;
    uint32_t d_addr;
};

struct EthIpPacket final {
    EthHdr eth_;
    IpHdr ip_;
};

char* get_my_MAC(const char* iface);
char* get_my_IP(const char* iface);
Mac get_others_MAC(pcap_t* handle, const char* dev, uint32_t s_IP, uint32_t m_IP, Mac m_MAC);
void send_arp(pcap_t* handle, const char* dev, Mac s_MAC, Mac m_MAC, uint32_t s_IP, uint32_t t_IP);
void relay(pcap_t* handle, struct pcap_pkthdr* header, const unsigned char* pkt_data, const char* dev, char* errbuf, Mac t_MAC, Mac m_MAC, Mac s_MAC, uint32_t s_IP, uint32_t t_IP);
void reinfect(pcap_t* handle, struct pcap_pkthdr* header, const unsigned char* pkt_data, char* errbuf,const char* dev, Mac s_MAC, Mac t_MAC, Mac m_MAC, uint32_t s_IP, uint32_t t_IP);
void usage();

#endif // MAIN_H
