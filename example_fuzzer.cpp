#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include "mac.h"
#include "ip.h"

// Fuzzer 엔트리 포인트
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32) return 0; // 입력 데이터가 너무 작으면 무시

    // 임의의 IP 주소 생성
    Ip send_ip(std::string(std::to_string(data[0]) + "." + std::to_string(data[1]) + "." + std::to_string(data[2]) + "." + std::to_string(data[3])));
    Ip target_ip(std::string(std::to_string(data[4]) + "." + std::to_string(data[5]) + "." + std::to_string(data[6]) + "." + std::to_string(data[7])));

    // 임의의 MAC 주소 생성
    Mac send_mac = Mac::randomMac();
    Mac target_mac = Mac::randomMac();

    // ARP 스푸핑 프로그램 실행
    std::string send_ip_str = static_cast<std::string>(send_ip);
    std::string target_ip_str = static_cast<std::string>(target_ip);

    char* argv[] = { "arp-spoof", "wlan0", const_cast<char*>(send_ip_str.c_str()), const_cast<char*>(target_ip_str.c_str()) };
    int argc = sizeof(argv) / sizeof(argv[0]);

    get_my_MAC(argv[1]);

    return 0;
}
