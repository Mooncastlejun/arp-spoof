#include <stddef.h>
#include <stdint.h>
#include <iostream>
#include <cstring>
#include <map>
#include "arp_spoof.h"

// Fuzzing 테스트에 필요한 전역 상태 유지
std::map<Ip, Mac> ipmap;
char errbuf[PCAP_ERRBUF_SIZE]; // pcap 에러 버퍼

// Fuzzing 진입점
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Step 4: Creating a FILE pointer for reading from data
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (!in_file) return 0; // Handle error

    // Step 6: Define variables
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface = "eth0"; // Example interface
    char *my_ip_str = get_my_IP(iface);
    char *my_mac_str = get_my_MAC(iface);

    // Assuming IPs are encoded and can be derived from data (simple mock)
    uint32_t target_ip = inet_addr("192.168.1.10"); // Target IP to spoof
    uint32_t source_ip = inet_addr(my_ip_str); // Source IP is the one we got

    // Open pcap handle
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        free(my_ip_str);
        free(my_mac_str);
        fclose(in_file);
        return 0; // Handle error
    }

    // Step 3: Using APIs
    Mac my_mac(my_mac_str); // MAC 주소 설정
    Mac target_mac = get_others_MAC(handle, iface, source_ip, target_ip, my_mac);

    // Send ARP spoofing packets
    send_arp(handle, iface, my_mac, target_mac, source_ip, target_ip);

    // Relay and reinfect (Assuming a packet header and data)
    struct pcap_pkthdr header;
    const unsigned char *pkt_data = nullptr; // Should be filled with packet data
    reinfect(handle, &header, pkt_data, errbuf, iface, my_mac, target_mac, my_mac, source_ip, target_ip);
    relay(handle, &header, pkt_data, iface, errbuf, target_mac, my_mac, my_mac, source_ip, target_ip);

    // Free allocated resources
    free(my_ip_str);
    free(my_mac_str);
    pcap_close(handle);
    fclose(in_file);

    return 0; // Indicate success
}
