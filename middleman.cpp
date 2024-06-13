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
#include <sys/types.h>
#include <pwd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <regex>
#include <iomanip> // For std::setw and std::setfill

#define SERVER_PORT 99
#define PERMISSION_MIDDLEMAN_PORT 98
#define CLIENT_IP "127.0.0.1"
#define WHITELIST_FILE "/bin/oddbyte/whitelist"

struct WhitelistEntry {
    int id;
    std::string filePath;
    std::string fileHash;
    std::vector<std::string> allowedUsers;
};

bool isValidFilePath(const std::string &path) {
    return std::regex_match(path, std::regex("(/[^/ ]*)+/?"));
}

bool isValidUserName(const std::string &username) {
    return std::regex_match(username, std::regex("[a-zA-Z0-9_]+"));
}

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

bool checkPermissions(const std::string &user, const std::string &filePath, const std::unordered_map<int, WhitelistEntry> &whitelist) {
    for (const auto &entry : whitelist) {
        std::regex fileRegex(entry.second.filePath);
        if (!std::regex_match(filePath, fileRegex))
            continue;

        std::regex hashRegex(entry.second.fileHash);
        std::string fileHash = calculateFileHash(filePath);
        if (!std::regex_match(fileHash, hashRegex))
            continue;

        for (const std::string &allowedUser : entry.second.allowedUsers) {
            std::regex userRegex(allowedUser);
            if (std::regex_match(user, userRegex))
                return true;
        }
    }
    return false;
}

std::string getUserName(uid_t uid) {
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        return std::string(pw->pw_name);
    }
    return "";
}

bool isUserRoot() {
    return geteuid() == 0;
}

int getNextId(const std::unordered_map<int, WhitelistEntry>& whitelist) {
    int maxId = -1;
    for (const auto& entry : whitelist) {
        if (entry.first > maxId) {
            maxId = entry.first;
        }
    }
    return maxId + 1;
}

void handleRequest(int clientSocket, std::unordered_map<int, WhitelistEntry> &whitelist) {
    char buffer[1024] = {0};
    read(clientSocket, buffer, 1024);

    std::istringstream iss(buffer);
    std::string command;
    iss >> command;

    if (command == "CHECK") {
        std::string filePath;
        iss >> filePath;

        uid_t uid = getuid();
        std::string user = getUserName(uid);

        bool allowed = checkPermissions(user, filePath, whitelist);

        const char *response = allowed ? "Permission granted" : "Permission denied";
        send(clientSocket, response, strlen(response), 0);
    } else if (command == "EDIT" && isUserRoot()) {
        std::ofstream outfile(WHITELIST_FILE, std::ofstream::app);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.empty()) break;

            std::istringstream entry(line);
            std::string filePath, fileHash, users;
            std::getline(entry, filePath, '`');
            std::getline(entry, fileHash, '`');
            std::getline(entry, users, '`');

            if (!isValidFilePath(filePath)) {
                std::cerr << "Invalid file path: " << filePath << std::endl;
                continue;
            }

            if (!std::regex_match(fileHash, std::regex("[a-fA-F0-9]{64}|FILE"))) {
                std::cerr << "Invalid file hash: " << fileHash << std::endl;
                continue;
            }

            std::vector<std::string> allowedUsers;
            std::stringstream ss(users);
            std::string user;
            while (std::getline(ss, user, ':')) { // Use ':' as delimiter
                if (isValidUserName(user)) {
                    uid_t uid = getpwnam(user.c_str())->pw_uid; // Convert std::string to const char*
                    allowedUsers.push_back(std::to_string(uid));
                } else {
                    std::cerr << "Invalid username: " << user << std::endl;
                }
            }

            int id = getNextId(whitelist);
            outfile << id << '`' << filePath << '`' << fileHash << '`';
            for (size_t i = 0; i < allowedUsers.size(); ++i) {
                outfile << allowedUsers[i];
                if (i < allowedUsers.size() - 1) {
                    outfile << ":";
                }
            }
            outfile << '\n';

            WhitelistEntry newEntry = {id, filePath, fileHash, allowedUsers};
            whitelist[id] = newEntry;
        }
        outfile.close();
        const char *response = "Whitelist updated";
        send(clientSocket, response, strlen(response), 0);
    } else if (command == "LIST") {
        std::ostringstream oss;
        for (const auto &entry : whitelist) {
            oss << entry.first << " " << entry.second.filePath << " " << entry.second.fileHash << " ";
            for (size_t i = 0; i < entry.second.allowedUsers.size(); ++i) {
                oss << entry.second.allowedUsers[i];
                if (i < entry.second.allowedUsers.size() - 1) {
                    oss << ":";
                }
            }
            oss << "\n";
        }
        std::string response = oss.str();
        send(clientSocket, response.c_str(), response.size(), 0);
    } else {
        const char *response = "Invalid command or insufficient permissions";
        send(clientSocket, response, strlen(response), 0);
    }
}

int main() {
    if (!isUserRoot()) {
        std::cerr << "Permission Middleman must be run as root." << std::endl;
        return EXIT_FAILURE;
    }

    auto whitelist = loadWhitelist();
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
    address.sin_port = htons(PERMISSION_MIDDLEMAN_PORT);

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

    std::cout << "Permission Middleman listening on port " << PERMISSION_MIDDLEMAN_PORT << std::endl;

    while ((clientSocket = accept(serverFd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
        if (strcmp(inet_ntoa(address.sin_addr), CLIENT_IP) != 0) {
            std::cerr << "Connection from unauthorized IP" << std::endl;
            close(clientSocket);
            continue;
        }

        handleRequest(clientSocket, whitelist);
        close(clientSocket);
    }

    close(serverFd);
    return 0;
}
