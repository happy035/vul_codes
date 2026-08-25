#include <iostream>
#include <cstring>

/**
 * Vulnerability Pattern: Classic Stack Buffer Overflow (CWE-120 / CWE-676)
 * 
 * Description:
 * Using unsafe legacy string functions such as `strcpy` or `gets` without bounds checking
 * can lead to stack memory corruption.
 * 
 * Target SAST Rule: Flag unsafe C-string handling functions (strcpy, strcat, sprintf, gets)
 * where destination buffer capacity is smaller or unchecked relative to source data.
 */

void parse_network_packet_vulnerable(const char* packet_payload) {
    char local_buffer[64];

    // Vulnerable: strcpy does not check the length of packet_payload against the capacity of local_buffer.
    std::strcpy(local_buffer, packet_payload);
    std::cout << "[Vulnerable] Parsed buffer: " << local_buffer << std::endl;
}

/**
 * Remediation / Fix Strategy:
 * 1. Use modern C++ types like std::string or std::string_view that manage bounds automatically.
 * 2. If working with raw buffers, use bounded functions like strncpy / snprintf with explicit size bounds.
 */
void parse_network_packet_fixed(const std::string& packet_payload) {
    // Fixed: Using std::string directly or checking bounds explicitly
    constexpr size_t MAX_SAFE_SIZE = 63;
    if (packet_payload.size() > MAX_SAFE_SIZE) {
        std::cerr << "[Fixed] Payload exceeds maximum buffer capacity. Truncating or rejecting." << std::endl;
        return;
    }

    char local_buffer[64];
    std::strncpy(local_buffer, packet_payload.c_str(), sizeof(local_buffer) - 1);
    local_buffer[sizeof(local_buffer) - 1] = '\0';

    std::cout << "[Fixed] Parsed buffer safely: " << local_buffer << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <payload>" << std::endl;
        return 1;
    }

    parse_network_packet_vulnerable(argv[1]);
    parse_network_packet_fixed(argv[1]);

    return 0;
}