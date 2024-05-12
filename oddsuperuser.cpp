#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <ctime>
#include <sys/stat.h>
#include <libgen.h>
#include <termios.h>
#include <sys/wait.h>

using namespace CryptoPP;
using namespace std;

const string SUPERKEY_FILE = "/etc/SuperKey";
const char* RED = "\033[1;31m";
const char* GREEN = "\033[1;32m";
const char* YELLOW = "\033[1;33m";
const char* RESET = "\033[0m";
const string TARGET_PATH = "/usr/bin/osu";

struct SuperKey {
    int id;
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

string getPasswordInput() {
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt); // get old settings
    newt = oldt;
    newt.c_lflag &= ~(ECHO); // turn off echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    string password;
    getline(cin, password);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // restore old settings
    return password;
}

unordered_map<string, SuperKey> loadSuperKeys() {
    unordered_map<string, SuperKey> superKeys;
    ifstream inFile(SUPERKEY_FILE);
    string line;

    while (getline(inFile, line)) {
        stringstream ss(line);
        string idStr, name, hash, users, commands;
        getline(ss, idStr, ':');
        getline(ss, name, ':');
        getline(ss, hash, ':');
        getline(ss, users, ':');
        getline(ss, commands);

        int id = stoi(idStr); // Convert the ID string to a Int

        SuperKey sk{id, name, hash, users, commands};
        superKeys[hash] = sk;
    }

    inFile.close();
    return superKeys;
}

void saveSuperKey(const SuperKey& sk) {
    ofstream outFile(SUPERKEY_FILE, ios_base::app);
    outFile << sk.id << ":" << sk.readableName << ":" << sk.superKeyHash << ":" << sk.allowedUsers << ":" << sk.allowedCommands << endl;
    outFile.close();
}

void createInitialSuperKey() {
    cout << "Creating initial SuperKey..." << endl;

    SuperKey sk;
    sk.id = 0;
    sk.readableName = "Initial SuperKey";
    cout << GREEN << "Enter the SuperKey" << RED << " [DANGER: This SuperKey is like the password to your system. Make sure that this is secure, and DO NOT share this key. Sharing this key will give an attacker full access over your system!]: ";
    string password = getPasswordInput();
    sk.superKeyHash = generateSHA256(password);
    sk.allowedUsers = "*";
    sk.allowedCommands = "*";

    saveSuperKey(sk);
    cout << "SuperKey created successfully with ID: " << sk.id << "\n";
}

void ensureCorrectEnvironment(bool forceInstall) {
    char actualpath[PATH_MAX+1];
    char *ptr = realpath("/proc/self/exe", actualpath);

    // Handle forced installation
    if (forceInstall) {
        remove(TARGET_PATH.c_str()); // Remove the existing executable
        remove(SUPERKEY_FILE.c_str()); // Remove the existing SuperKey file
        cout << GREEN << "Forced reinstallation initiated." << RESET << endl;
    }

    // Check if running at the correct path and with the correct permissions
    if (string(ptr) != TARGET_PATH || forceInstall) {
        cerr << RED << "Executable is not in the correct path or installation is underway." << RESET << endl;
        if (getuid() == 0) { // Only proceed if root
            cerr << GREEN << "Installing at " << TARGET_PATH << "..." << RESET << endl;
            string command = "cp " + string(ptr) + " " + TARGET_PATH + " && chmod 7555 " + TARGET_PATH + " && chown root:root " + TARGET_PATH;
            system(command.c_str());
            createInitialSuperKey();
        } else {
            cerr << RED << "Please run as root to install properly." << RESET << endl;
            exit(1);
        }
    }

    // Check if the SuperKey file exists
    struct stat buffer;
    if (stat(SUPERKEY_FILE.c_str(), &buffer) != 0) {
        cerr << YELLOW << "SuperKey file does not exist. Creating one." << RESET << endl;
        createInitialSuperKey();
    }
}

void listPermissions(const string& users, const string& commands) {
    cout << YELLOW << "Allowed users: " << RESET << users << endl;
    cout << YELLOW << "Allowed commands: " << RESET << commands << endl;
}

// Function to check if a given username and command have permissions
bool hasPermission(const string& allowedUsers, const string& allowedCommands, const string& username, const string& command) {
    vector<string> users, commands;
    stringstream ssUsers(allowedUsers), ssCommands(allowedCommands);
    string item;

    // Parse allowed users
    while (getline(ssUsers, item, ',')) users.push_back(item);

    // Parse allowed commands
    while (getline(ssCommands, item, ';')) commands.push_back(item);

    // Check if the username is allowed
    bool userAllowed = find(users.begin(), users.end(), username) != users.end() || find(users.begin(), users.end(), "*") != users.end();
    
    // Check if the command is allowed
    bool commandAllowed = find(commands.begin(), commands.end(), command) != commands.end() || find(commands.begin(), commands.end(), "*") != commands.end();
    
    // If not allowed, list the permissions
    if (!userAllowed || !commandAllowed) {
        listPermissions(allowedUsers, allowedCommands);
    }
    
    return userAllowed && commandAllowed;
}

int main(int argc, char* argv[]) {
    int opt;
    bool forceInstall = false;
    string username = "root";
    string command = "/bin/bash";  // Default command

    static struct option long_options[] = {
        {"user", required_argument, nullptr, 'u'},
        {"command", required_argument, nullptr, 'c'},
        {"install-force", no_argument, nullptr, 0},
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
            case 0:
                if (string(long_options[optind - 1].name) == "install-force") {
                    forceInstall = true;
                }
                break;
            default:
                cout << RED << "Invalid usage." << RESET << endl;
                return 1;
        }
    }

    ensureCorrectEnvironment(forceInstall);

    if (!forceInstall) {
        unordered_map<string, SuperKey> superKeys = loadSuperKeys();
        cout << GREEN << "Enter SuperKey: " << RESET;
        string inputKey = getPasswordInput();
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

        // Clear all environment variables
        clearenv();

        // Set necessary environment variables
        setenv("HOME", pwd->pw_dir, 1);
        setenv("USER", username.c_str(), 1);
        setenv("LOGNAME", username.c_str(), 1);
        setenv("SHELL", pwd->pw_shell, 1);
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin", 1);  // Normal PATH; adjust as needed
        setenv("color_prompt", "yes", 1);

        if (setgid(pwd->pw_gid) != 0 || setuid(pwd->pw_uid) != 0 || seteuid(pwd->pw_uid) != 0) {
            cerr << RED << "Failed to change user/group ID." << RESET << endl;
            return 1;
        }

        // Execute the command
        char* newargv[] = {strdup(command.c_str()), nullptr}; // Command to execute
        char* newenviron[] = {nullptr}; // Empty environment
        execve(command.c_str(), newargv, newenviron);
        perror("execve"); // execve only returns on error
    }

    return 0;
}
