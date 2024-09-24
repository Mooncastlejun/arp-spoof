extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Check if size is valid
    if (size < 1) return 0;

    // Step 2: Read the input data into a FILE pointer
    FILE *in_file = fmemopen((void *)data, size, "rb");
    if (!in_file) return 0;

    char iface[IFNAMSIZ]; // Interface name
    char errbuf[PCAP_ERRBUF_SIZE]; // Error buffer
    uint32_t src_ip = 0; // Source IP initialized to zero
    uint32_t target_ip = 0; // Target IP initialized to zero
    Mac src_mac, target_mac, my_mac;

    // 예시 인터페이스 이름 설정
    snprintf(iface, sizeof(iface), "eth0"); // Use an example interface name

    // Get our MAC and IP
    char *my_mac_str = get_my_MAC(iface); // MAC 주소를 char*로 가져옴
    my_mac = Mac(my_mac_str); // char*를 Mac 객체로 변환
    char *my_ip = get_my_IP(iface);

    // Open a pcap handle for the specified device
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fclose(in_file);
        return 0;
    }

    // Retrieve the MAC of another device based on simulated IPs
    target_mac = get_others_MAC(handle, iface, src_ip, target_ip, my_mac);

    // Simulated packet data for relay
    struct pcap_pkthdr header;
    const unsigned char *pkt_data = nullptr; // 여기서 입력 데이터에 따라 채워야 합니다.

    // Execute relay
    relay(handle, &header, pkt_data, iface, errbuf, target_mac, my_mac, src_mac, src_ip, target_ip);

    // Execute reinfect
    reinfect(handle, &header, pkt_data, errbuf, iface, src_mac, target_mac, my_mac, src_ip, target_ip);

    // Clean up
    pcap_close(handle);
    fclose(in_file);
    free(my_mac_str); // 할당된 메모리 해제

    return 0; // Indicate successful execution
}
