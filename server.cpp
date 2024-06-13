#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iomanip> // For std::setw and std::setfill
#include <cstdlib>

#define PORT 99
#define PERMISSION_HANDLER_IP "127.0.0.1"
#define WHITELIST_FILE "/bin/oddbyte/whitelist"

struct WhitelistEntry {
    int id;
    std::string filePath;
    std::string fileHash;
    std::vector<std::string> allowedUsers;
};

std::unordered_map<int, WhitelistEntry> loadWhitelist() {
    std::unordered_map<int, WhitelistEntry> whitelist;
    std::ifstream infile(WHITELIST_FILE);
    std::string line;

    while (std::getline(infile, line)) {
        if (line.empty() || line[0] == '#')
            continue;

        std::istringstream iss(line);
        std::string id_str, filePath, fileHash, users;
        std::getline(iss, id_str, '`');
        std::getline(iss, filePath, '`');
        std::getline(iss, fileHash, '`');
        std::getline(iss, users, '`');

        int id = std::stoi(id_str);
        std::vector<std::string> allowedUsers;
        std::stringstream ss(users);
        std::string user;
        while (std::getline(ss, user, ':')) { // Use ':' as delimiter
            if (user != ":")
                allowedUsers.push_back(user);
        }

        WhitelistEntry entry = {id, filePath, fileHash, allowedUsers};
        whitelist[id] = entry;
    }

    return whitelist;
}

std::string calculateFileHash(const std::string &filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return "";
    }

    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(&buffer[0], buffer.size(), hash);

    std::ostringstream result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return result.str();
}

void updateWhitelistHashes() {
    auto whitelist = loadWhitelist();
    std::ofstream outfile(WHITELIST_FILE);
    for (const auto &entry : whitelist) {
        std::string fileHash = entry.second.fileHash;
        if (fileHash == "FILE") {
            fileHash = calculateFileHash(entry.second.filePath);
        }
        outfile << entry.second.id << '`' << entry.second.filePath << '`' << fileHash << '`';
        for (size_t i = 0; i < entry.second.allowedUsers.size(); ++i) {
            outfile << entry.second.allowedUsers[i];
            if (i < entry.second.allowedUsers.size() - 1) {
                outfile << ":";
            }
        }
        outfile << '\n';
    }
    outfile.close();
}

void handleClient(int clientSocket) {
    char buffer[1024] = {0};
    read(clientSocket, buffer, 1024);

    if (strcmp(buffer, "INTERACTIVE") == 0) {
        const char *response = "Starting interactive shell";
        send(clientSocket, response, strlen(response), 0);
        close(clientSocket);

        if (fork() == 0) {
            execl("/bin/bash", "bash", NULL);
            perror("execl failed");
            exit(EXIT_FAILURE);
        }
        wait(NULL);
    } else {
        const char *response = "Invalid request";
        send(clientSocket, response, strlen(response), 0);
        close(clientSocket);
    }
}

int main() {
    updateWhitelistHashes(); // Update hashes before starting

    int serverFd, clientSocket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((serverFd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        close(serverFd);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(serverFd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        close(serverFd);
        exit(EXIT_FAILURE);
    }

    if (listen(serverFd, 3) < 0) {
        perror("Listen failed");
        close(serverFd);
        exit(EXIT_FAILURE);
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    while ((clientSocket = accept(serverFd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
        if (strcmp(inet_ntoa(address.sin_addr), PERMISSION_HANDLER_IP) != 0) {
            std::cerr << "Connection from unauthorized IP" << std::endl;
            close(clientSocket);
            continue;
        }

        handleClient(clientSocket);
    }

    close(serverFd);
    return 0;
}
