#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <string>
#include <cstdlib>
#include <vector>
#include <termios.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;
using std::string;
using std::vector;

string generateSHA256(const string& input) {
    SHA256 hash;
    string digest;

    StringSource s(input, true,
        new HashFilter(hash,
            new HexEncoder(
                new StringSink(digest)
            )
        )
    );

    return digest;
}

bool isRoot() {
    return geteuid() == 0;
}

// Function to read the input key securely
string readSecureLine() {
    string input;
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt); // Get current terminal attributes
    newt = oldt;
    newt.c_lflag &= ~(ECHO); // Disable echoing of typed characters
    tcsetattr(STDIN_FILENO, TCSANOW, &newt); // Set new attributes

    getline(std::cin, input); // Read the input without echo

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // Restore old attributes
    std::cout << std::endl;
    return input;
}

bool verifySuperKey(const string& keyPath, const string& inputKey) {
    std::ifstream inFile(keyPath);
    string storedHash;
    if (inFile.is_open()) {
        std::getline(inFile, storedHash);
        inFile.close();
        return generateSHA256(inputKey) == storedHash;
    }
    return false;
}

bool checkFileSecurity(const string& path, mode_t expectedMode, uid_t expectedUid, gid_t expectedGid) {
    struct stat fileInfo;
    if (stat(path.c_str(), &fileInfo) != 0) {
        return false; // File does not exist or cannot be accessed
    }
    if ((fileInfo.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != expectedMode) {
        return false; // Permissions do not match expected
    }
    if (fileInfo.st_uid != expectedUid || fileInfo.st_gid != expectedGid) {
        return false; // Owner or group does not match expected
    }
    return true;
}

void installAsRoot(const string& targetPath, const string& keyPath) {
    const char* sourcePath = "/proc/self/exe";
    std::string command = "cp " + string(sourcePath) + " " + targetPath;
    system(command.c_str());
    chmod(targetPath.c_str(), S_ISUID | S_ISGID | S_IRUSR | S_IWUSR | S_IXUSR);  // Set setuid and setgid bits
    chown(targetPath.c_str(), 0, 0);

    // Create key file if it does not exist
    struct stat buffer;
    if (stat(keyPath.c_str(), &buffer) != 0) {
        std::cout << "Please create your SuperKey: ";
        string superKey = readSecureLine();
        string superKeyHash = generateSHA256(superKey);

        std::ofstream outFile(keyPath, std::ios_base::out);
        outFile << superKeyHash;
        outFile.close();
        chmod(keyPath.c_str(), S_IRUSR); // Readable by root only
        chown(keyPath.c_str(), 0, 0);
    }
}

uid_t getUserID(const string& user) {
    if (isdigit(user[0])) {
        return atoi(user.c_str());
    } else {
        struct passwd *pwd = getpwnam(user.c_str());
        if (pwd) {
            return pwd->pw_uid;
        } else {
            throw std::runtime_error("User does not exist: " + user);
        }
    }
}

int main(int argc, char* argv[]) {
    string installPath = "/usr/bin/osu";
    string keyPath = "/usr/bin/oukey";
    string user = "root";
    vector<string> command;
    bool executeCommand = false;

    int i = 1;
    while (i < argc) {
        string arg = argv[i];
        if (arg == "-u" && i + 1 < argc) {
            user = argv[++i];
        } else if (arg == "-c" && i + 1 < argc) {
            executeCommand = true;
            while (++i < argc) {
                command.push_back(argv[i]);
            }
            break; // Everything after -c is part of the command
        }
        i++;
    }
    
    try {
        if (isRoot()) {
            if (!checkFileSecurity(installPath, S_ISUID | S_ISGID | S_IRUSR | S_IWUSR | S_IXUSR, 0, 0) ||
                !checkFileSecurity(keyPath, S_IRUSR, 0, 0)) {
                installAsRoot(installPath, keyPath);
            }
        }
        
        std::cout << "Enter SuperKey to gain access: ";
        string inputKey = readSecureLine();

        if (verifySuperKey(keyPath, inputKey)) {
            uid_t uid = getUserID(user);
            setuid(uid);  // Set user ID
            setgid(getpwuid(uid)->pw_gid);  // Set group ID
            std::cout << "\nAccess granted. You are now " << user << "." << std::endl;

            if (executeCommand) {
                string fullCommand;
                for (const string& part : command) {
                    fullCommand += part + " ";
                }
                system(fullCommand.c_str());
            } else {
                system("/bin/bash");  // Start a shell as the specified user
            }
        } else {
            std::cerr << "\nAccess denied. Incorrect SuperKey." << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
