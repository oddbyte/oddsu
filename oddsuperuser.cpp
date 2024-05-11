#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <cstdlib>
#include <cstring>
#include <getopt.h>

using namespace CryptoPP;
using namespace std;

const string SUPERKEY_FILE = "/etc/SuperKey";
const char* RED = "\033[1;31m";
const char* GREEN = "\033[1;32m";
const char* YELLOW = "\033[1;33m";
const char* RESET = "\033[0m";

struct SuperKey {
    string id;
    string readableName;
    string superKeyHash;
    string allowedUsers;
    string allowedCommands;
};

string generateSHA256(const string& input) {
    SHA256 hash;
    string digest;
    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
    return digest;
}

unordered_map<string, SuperKey> loadSuperKeys() {
    unordered_map<string, SuperKey> superKeys;
    ifstream inFile(SUPERKEY_FILE);
    string line;

    while (getline(inFile, line)) {
        stringstream ss(line);
        string id, name, hash, users, commands;
        getline(ss, id, ':');
        getline(ss, name, ':');
        getline(ss, hash, ':');
        getline(ss, users, ':');
        getline(ss, commands);

        SuperKey sk{id, name, hash, users, commands};
        superKeys[hash] = sk;
    }

    inFile.close();
    return superKeys;
}

void listPermissions(const string& users, const string& commands) {
    cout << YELLOW << "Allowed users: " << RESET << users << endl;
    cout << YELLOW << "Allowed commands: " << RESET << commands << endl;
}

bool hasPermission(const string& allowedUsers, const string& allowedCommands, const string& username, const string& command) {
    vector<string> users, commands;
    stringstream ssUsers(allowedUsers), ssCommands(allowedCommands);
    string item;

    while (getline(ssUsers, item, ',')) users.push_back(item);
    while (getline(ssCommands, item, ';')) commands.push_back(item);

    bool userAllowed = find(users.begin(), users.end(), username) != users.end() || find(users.begin(), users.end(), "*") != users.end();
    bool commandAllowed = find(commands.begin(), commands.end(), command) != commands.end() || find(commands.begin(), commands.end(), "*") != commands.end();
    
    if (!userAllowed || !commandAllowed) {
        listPermissions(allowedUsers, allowedCommands);
    }
    
    return userAllowed && commandAllowed;
}

int main(int argc, char* argv[]) {
    string username, command;
    int opt;

    if (argc < 2) {
        cout << RED << "Usage: " << argv[0] << " -u <username> -c <command>" << RESET << endl;
        return 1;
    }

    static struct option long_options[] = {
        {"user", required_argument, nullptr, 'u'},
        {"command", required_argument, nullptr, 'c'},
        {nullptr, 0, nullptr, 0}
    };

    while ((opt = getopt_long(argc, argv, "u:c:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'u':
                username = optarg;
                break;
            case 'c':
                command = optarg;
                break;
            default:
                cout << RED << "Invalid usage." << RESET << endl;
                return 1;
        }
    }

    unordered_map<string, SuperKey> superKeys = loadSuperKeys();
    cout << GREEN << "Enter SuperKey: " << RESET;
    string inputKey;
    getline(cin, inputKey);
    string hashedInput = generateSHA256(inputKey);

    auto it = superKeys.find(hashedInput);
    if (it == superKeys.end()) {
        cerr << RED << "Access denied. Incorrect SuperKey." << RESET << endl;
        return 1;
    }

    const SuperKey& sk = it->second;
    if (!hasPermission(sk.allowedUsers, sk.allowedCommands, username, command)) {
        cerr << RED << "Access denied. You do not have permission for this user/command." << RESET << endl;
        return 1;
    }

    struct passwd* pwd = getpwnam(username.c_str());
    if (!pwd) {
        cerr << RED << "User does not exist: " << username << RESET << endl;
        return 1;
    }

    if (setgid(pwd->pw_gid) != 0 || setuid(pwd->pw_uid) != 0) {
        cerr << RED << "Failed to change user and group ID." << RESET << endl;
        return 1;
    }

    system(command.c_str());
    return 0;
}
