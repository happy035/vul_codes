#include <iostream>
#include <string>
#include <cstdlib>

/**
 * Vulnerability Pattern: Command Injection (CWE-78 / CWE-88)
 * 
 * Description:
 * Directly passing untrusted user input to a system shell command execution function
 * (like std::system or popen) allows an attacker to inject arbitrary commands.
 * 
 * Target SAST Rule: Look for standard command execution APIs where arguments contain
 * unescaped/unvalidated string concatenations from external inputs.
 */

void execute_ping_vulnerable(const std::string& host_input) {
    // Vulnerable: user input is concatenated directly into a shell command string.
    std::string command = "ping -c 1 " + host_input;
    std::cout << "[Vulnerable] Executing: " << command << std::endl;
    std::system(command.c_str());
}

/**
 * Remediation / Fix Strategy:
 * 1. Validate and strictly sanitize the input (e.g., ensure it is a valid IPv4/IPv6/hostname format).
 * 2. Avoid passing commands to the shell (std::system). Use exec-family functions (e.g., execve, posix_spawn)
 *    passing arguments as an array rather than a single interpolated shell string.
 */
void execute_ping_fixed(const std::string& host_input) {
    // Basic whitelist validation: verify host contains only alphanumeric characters, dots, and hyphens.
    bool valid = !host_input.empty() && host_input.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") == std::string::npos;
    
    if (!valid) {
        std::cerr << "[Fixed] Invalid hostname provided. Aborting execution." << std::endl;
        return;
    }

    std::cout << "[Fixed] Validated host: " << host_input << std::endl;
    // In production, invoke via fork/execv or a platform-specific process API rather than std::system.
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <host>" << std::endl;
        return 1;
    }
    
    std::string input = argv[1];
    execute_ping_vulnerable(input);
    execute_ping_fixed(input);

    return 0;
}