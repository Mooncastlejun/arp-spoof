#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

// IP와 MAC 구조체 정의 (기존의 코드에 맞춰 수정 필요)
struct Ip {
    uint32_t addr;
    Ip() : addr(0) {}
    Ip(const char* ip) { addr = inet_addr(ip); }
    bool operator==(const Ip& other) const { return addr == other.addr; }
    bool operator!=(const Ip& other) const { return !(*this == other); }
};

struct Mac {
    uint8_t addr[6];
    Mac() { memset(addr, 0, sizeof(addr)); }
    Mac(const char* mac) {
        sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);
    }
    bool operator==(const Mac& other) const { return memcmp(addr, other.addr, sizeof(addr)) == 0; }
};

// Fuzzer 엔트리 포인트
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32) return 0; // 입력 데이터가 너무 작으면 무시

    // 임의의 IP 주소 생성
    char send_ip_str[16];
    char target_ip_str[16];
    
    snprintf(send_ip_str, sizeof(send_ip_str), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);
    snprintf(target_ip_str, sizeof(target_ip_str), "%d.%d.%d.%d", data[4], data[5], data[6], data[7]);

    // ARP 스푸핑 프로그램 실행
    char *argv[] = { "arp-spoof", "wlan0", send_ip_str, target_ip_str };
    int argc = sizeof(argv) / sizeof(argv[0]);

    // 기존 main 함수 호출 (argv와 argc 전달)
    main(argc, argv); // main 함수에 직접 전달 (조정 필요)

    return 0;
}
