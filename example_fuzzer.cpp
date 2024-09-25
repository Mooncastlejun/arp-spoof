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
    // 최소 두 개의 IP 주소와 네트워크 인터페이스 길이를 위한 데이터 크기 확인
    if (size < 2 * sizeof(Ip) + 1) {
        return 0; // 데이터 크기가 부족할 경우 종료
    }

    // 인터페이스 이름 고정
    const char* dev = "eth0"; // Use a valid network interface

    // IP 주소 추출 (첫 번째 IP는 보낸 IP, 두 번째 IP는 타겟 IP)
    const Ip send_IP = *reinterpret_cast<const Ip*>(data + 1);
    const Ip tar_IP = *reinterpret_cast<const Ip*>(data + 1 + sizeof(Ip));

    // MAC 주소 얻기 (랜덤 MAC 주소로 초기화)
    uint8_t mac[Mac::SIZE]; // 배열로 정의
    get_my_MAC(mac); // MAC 주소를 mac 배열에 저장
    Mac my_MAC(mac);

    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s(%s)\n", dev, errbuf);
        return 0;
    }

    // IP 주소에 해당하는 MAC 주소 찾기 또는 얻기
    Mac send_MAC, tar_MAC;
    if (ipmap.find(send_IP) != ipmap.end()) {
        send_MAC = ipmap[send_IP];
    } else {
        send_MAC = get_others_MAC(handle, const_cast<char*>(dev), send_IP, Ip(get_my_IP(dev)), my_MAC);
        ipmap[send_IP] = send_MAC;
    }

    if (ipmap.find(tar_IP) != ipmap.end()) {
        tar_MAC = ipmap[tar_IP];
    } else {
        tar_MAC = get_others_MAC(handle, const_cast<char*>(dev), tar_IP, Ip(get_my_IP(dev)), my_MAC);
        ipmap[tar_IP] = tar_MAC;
    }

    // ARP 전송 (보낸 IP와 타겟 IP 사이)
    send_arp(handle, const_cast<char*>(dev), send_MAC, my_MAC, send_IP, tar_IP);
    send_arp(handle, const_cast<char*>(dev), tar_MAC, my_MAC, tar_IP, send_IP);

    // 패킷 수신 및 처리
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pkt_data;
        int res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 0) {
            continue; // 패킷이 없으면 다음 패킷 기다리기
        }

        // 받은 패킷에 대해 relay와 reinfect 수행
        relay(handle, header, pkt_data, const_cast<char*>(dev), errbuf, tar_MAC, my_MAC, send_MAC, send_IP, tar_IP);
        reinfect(handle, header, pkt_data, errbuf, const_cast<char*>(dev), send_MAC, tar_MAC, my_MAC, send_IP, tar_IP);
    }

    // 자원 정리
    pcap_close(handle);
    return 0;
}
