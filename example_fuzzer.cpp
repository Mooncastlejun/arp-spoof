#include <stddef.h>
#include <stdint.h>
#include <iostream>
#include <cstring>
#include <map>
#include <pcap.h> // pcap 관련 헤더 파일 포함
#include "arp_spoof.h" // ARP 스푸핑 관련 헤더 파일

// Fuzzing 테스트에 필요한 전역 상태 유지
std::map<Ip, Mac> ipmap; // IP 주소와 MAC 주소의 매핑을 위한 맵
char errbuf[PCAP_ERRBUF_SIZE]; // pcap 에러 버퍼

// Fuzzing 진입점
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 1. 최소 두 개의 IP 주소와 네트워크 인터페이스 길이를 위한 데이터 크기 확인
    if (size < 2 * sizeof(Ip) + 1) {
        return 0; // 데이터 크기가 부족할 경우 종료
    }

    // 2. 첫 번째 바이트를 인터페이스 길이로 사용
    uint8_t iface_len = data[0];
    if (iface_len >= size) {
        return 0; // 인터페이스 길이가 데이터 크기를 초과할 경우 종료
    }

    // 3. 인터페이스 이름 추출
    const char* dev = reinterpret_cast<const char*>(data + 1);

    // 4. IP 주소 추출 (첫 번째 IP는 보낸 IP, 두 번째 IP는 타겟 IP)
    const Ip send_IP = *reinterpret_cast<const Ip*>(data + iface_len + 1);
    const Ip tar_IP = *reinterpret_cast<const Ip*>(data + iface_len + 1 + sizeof(Ip));

    // 5. MAC 주소 얻기 (랜덤 MAC 주소로 초기화)
    char* mac = get_my_MAC(dev);
    Mac my_MAC(mac);
    
    // 6. pcap 핸들러 초기화
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s(%s)\n", dev, errbuf);
        return 0;
    }

    // 7. IP 주소에 해당하는 MAC 주소 찾기 또는 얻기
    Mac send_MAC, tar_MAC;
    if (ipmap.find(send_IP) != ipmap.end()) {
        send_MAC = ipmap[send_IP];
    } else {
        send_MAC = get_others_MAC(handle, dev, send_IP, Ip(get_my_IP(dev)), my_MAC);
        ipmap[send_IP] = send_MAC; // 새로 얻은 MAC 주소 저장
    }

    if (ipmap.find(tar_IP) != ipmap.end()) {
        tar_MAC = ipmap[tar_IP];
    } else {
        tar_MAC = get_others_MAC(handle, dev, tar_IP, Ip(get_my_IP(dev)), my_MAC);
        ipmap[tar_IP] = tar_MAC; // 새로 얻은 MAC 주소 저장
    }

    // 8. ARP 전송 (보낸 IP와 타겟 IP 사이)
    send_arp(handle, dev, send_MAC, my_MAC, send_IP, tar_IP);
    send_arp(handle, dev, tar_MAC, my_MAC, tar_IP, send_IP);

    // 9. 패킷 수신 및 처리
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* pkt_data;
        int res = pcap_next_ex(handle, &header, &pkt_data);
        if (res == 0) {
            continue; // 패킷이 없으면 다음 패킷 기다리기
        }

        // 10. 받은 패킷에 대해 relay와 reinfect 수행
        relay(handle, header, pkt_data, dev, errbuf, tar_MAC, my_MAC, send_MAC, send_IP, tar_IP);
        reinfect(handle, header, pkt_data, errbuf, dev, send_MAC, tar_MAC, my_MAC, send_IP, tar_IP);
    }

    // 11. 자원 정리
    pcap_close(handle); // pcap 핸들 닫기
    free(mac); // 동적 메모리 해제
    return 0; // 정상 종료
}
