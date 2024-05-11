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
#include <limits.h>

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

string readSecureLine() {
    string input;
    termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    getline(std::cin, input);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
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
        return false;
    }
    if ((fileInfo.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != expectedMode) {
        return false;
    }
    if (fileInfo.st_uid != expectedUid || fileInfo.st_gid != expectedGid) {
        return false;
    }
    return true;
}

void installAsRoot(const string& targetPath, const string& keyPath) {
    char sourcePath[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", sourcePath, sizeof(sourcePath) - 1);
    if (len != -1) {
        sourcePath[len] = '\0';
        std::ifstream sourceFile(sourcePath, std::ios::binary);
        std::ofstream targetFile(targetPath, std::ios::binary);
        targetFile << sourceFile.rdbuf();
        sourceFile.close();
        targetFile.close();

        chmod(targetPath.c_str(), S_ISUID | S_ISGID | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        chown(targetPath.c_str(), 0, 0);

        struct stat buffer;
        if (stat(keyPath.c_str(), &buffer) != 0) {
            std::cout << "\033[1;33mPlease create your SuperKey: \033[0m";
            string superKey = readSecureLine();
            string superKeyHash = generateSHA256(superKey);

            std::ofstream outFile(keyPath, std::ios_base::out);
            outFile << superKeyHash;
            outFile.close();
            chmod(keyPath.c_str(), S_IRUSR);
            chown(keyPath.c_str(), 0, 0);
        }
    } else {
        std::cerr << "\033[1;31mFailed to get the path of the running executable.\033[0m" << std::endl;
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
    string keyPath = "/usr/bin/osukey";
    string user = "root";
    vector<string> command;
    bool executeCommand = false;

    bool needReinstall = true;
    struct stat installStat;
    if (stat(installPath.c_str(), &installStat) == 0) {
        needReinstall = (installStat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) == (S_ISUID | S_ISGID | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) &&
                        installStat.st_uid == 0 && installStat.st_gid == 0;
    }

    if (needReinstall) {
        if (isRoot()) {
            installAsRoot(installPath, keyPath);
        } else {
            std::cerr << "\033[1;31mPlease run OddSU as root to install or set correct permissions.\033[0m" << std::endl;
            return 1;
        }
    }

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
            break;
        }
        i++;
    }
    
    try {
        std::cout << "Enter SuperKey to gain access: ";
        string inputKey = readSecureLine();

        if (verifySuperKey(keyPath, inputKey)) {
            uid_t uid = getUserID(user);
            setuid(uid);
            setgid(getpwuid(uid)->pw_gid);
            std::cout << "\nAccess granted. You are now " << user << "." << std::endl;

            if (executeCommand) {
                string fullCommand;
                for (const string& part : command) {
                    fullCommand += part + " ";
                }
                system(fullCommand.c_str());
            } else {
                system("/bin/bash");
            }
        } else {
            std::cerr << "\033[1;31mAccess denied. Incorrect SuperKey.\033[0m" << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "\033[1;31mError: " << e.what() << "\033[0m" << std::endl;
        return 1;
    }

    return 0;
}
