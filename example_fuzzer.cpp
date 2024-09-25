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
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (!in_file) return 0; // 에러 처리

    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface = "eth0"; // 예제 인터페이스
    char *my_ip_str = get_my_IP(iface);
    char *my_mac_str = get_my_MAC(iface);

    uint32_t target_ip = inet_addr("192.168.1.10"); // 스푸핑할 대상 IP
    uint32_t source_ip = inet_addr(my_ip_str); // 소스 IP

    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        free(my_ip_str);
        free(my_mac_str);
        fclose(in_file);
        return 0; // 에러 처리
    }

    // MAC 주소 객체 생성
    Mac my_mac(my_mac_str); // 문자열로부터 MAC 객체 생성

    // 대상 MAC 주소를 얻기
    Mac target_mac = get_others_MAC(handle, iface, source_ip, target_ip, my_mac);

    // ARP 스푸핑 패킷 전송
    send_arp(handle, iface, my_mac, target_mac, source_ip, target_ip);

    // 패킷 헤더 및 데이터 (가정)
    struct pcap_pkthdr header;
    const unsigned char *pkt_data = nullptr; // 패킷 데이터 채워야 함
    reinfect(handle, &header, pkt_data, errbuf, iface, my_mac, target_mac, my_mac, source_ip, target_ip);
    relay(handle, &header, pkt_data, iface, errbuf, target_mac, my_mac, my_mac, source_ip, target_ip);

    // 리소스 해제
    free(my_ip_str);
    free(my_mac_str);
    pcap_close(handle);
    fclose(in_file);

    return 0; // 성공 표시
}
