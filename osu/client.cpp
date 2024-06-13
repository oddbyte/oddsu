// client.cpp
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <sys/types.h>

#define SERVER_IP "127.0.0.1"
#define PERMISSION_MIDDLEMAN_PORT 98

bool isUserRoot() {
    return geteuid() == 0;
}

int main(int argc, char* argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[4096] = {0}; // Increased buffer size for listing entries
    std::string command = "CHECK";

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PERMISSION_MIDDLEMAN_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        return -1;
    }

    if (argc > 1) {
        std::string arg1 = argv[1];
        if (arg1 == "-c") {
            if (argc < 3) {
                std::cerr << "No command specified for -c option" << std::endl;
                return -1;
            }
            command = "CHECK ";
            command += argv[2];
        } else if (arg1 == "EDIT" && isUserRoot()) {
            std::string line;
            command = "EDIT";
            std::cout << "Enter new whitelist entries (end with EOF):" << std::endl;
            std::cin.ignore();
            while (std::getline(std::cin, line)) {
                if (line.empty()) break;
                command += "\n" + line;
            }
        } else if (arg1 == "LIST") {
            command = "LIST";
        } else {
            std::cerr << "Invalid command" << std::endl;
            return -1;
        }
    }

    send(sock, command.c_str(), command.size(), 0);
    read(sock, buffer, sizeof(buffer) - 1);
    std::cout << "Permission Middleman response:\n" << buffer << std::endl;

    close(sock);
    return 0;
}
