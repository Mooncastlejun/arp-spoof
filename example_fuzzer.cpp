#include <cstddef>
#include <cstdint>
#include <cstring>
#include <pcap.h>
#include <string>
#include <map>
#include <iostream>
#include "ethhdr.h"
#include "arphdr.h"

// Include any other necessary headers and define necessary structures
#include "main.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Check for valid input size
    if (Size < 1) return 0;

    // Create a string from the raw input
    std::string input(reinterpret_cast<const char*>(Data), Size);

    // Split the input into tokens (assuming the format: "interface ip1 ip2")
    char* args[3];
    int arg_count = 0;

    // Tokenize the input based on spaces or other delimiters
    char* token = strtok(const_cast<char*>(input.c_str()), " ");
    while (token != nullptr && arg_count < 3) {
        args[arg_count++] = token;
        token = strtok(nullptr, " ");
    }

    // Ensure we have the right number of arguments
    if (arg_count < 3) return 0;

    // Prepare the arguments for the main function
    char* dev = args[0];
    char* ip1 = args[1];
    char* ip2 = args[2];

    // Call the main function with the parsed arguments
    // Note: You need to modify the main function to take char** argv instead of int argc, char* argv[]
    char* new_argv[4] = { nullptr, dev, ip1, ip2 };
    int new_argc = 3; // argc will be 3 since we skip the program name

    // Initialize any other necessary components here
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return 0;
    }

    // Call the main logic of the program
    main(new_argc, new_argv);

    // Cleanup
    pcap_close(handle);
    
    return 0;
}
