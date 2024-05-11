#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <ctime>
#include <sstream>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

using namespace CryptoPP;
using namespace std;

const string SUPERKEY_FILE = "/etc/SuperKey";

string generateSHA256(const string& input) {
    SHA256 hash;
    string digest;
    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
    return digest;
}

struct SuperKey {
    string id;
    string readableName;
    string superKeyHash;
    string allowedUsers;
    string allowedCommands;
};

unordered_map<string, SuperKey> loadSuperKeys() {
    unordered_map<string, SuperKey> superKeys;
    ifstream inFile(SUPERKEY_FILE);
    string line;

    while (getline(inFile, line)) {
        stringstream ss(line);
        string segment;
        vector<string> seglist;

        while (getline(ss, segment, ':')) {
            seglist.push_back(segment);
        }

        if (seglist.size() < 5) continue;

        SuperKey sk{seglist[0], seglist[1], seglist[2], seglist[3], seglist[4]};
        superKeys[sk.id] = sk;
    }

    inFile.close();
    return superKeys;
}

void saveSuperKeys(const unordered_map<string, SuperKey>& superKeys) {
    ofstream outFile(SUPERKEY_FILE);
    for (const auto& pair : superKeys) {
        const auto& sk = pair.second;
        outFile << sk.id << ":" << sk.readableName << ":" << sk.superKeyHash << ":" << sk.allowedUsers << ":" << sk.allowedCommands << endl;
    }
    outFile.close();
}

string getCurrentTimeAsString() {
    time_t now = time(0);
    return to_string(now);
}

void addSuperKey(unordered_map<string, SuperKey>& superKeys) {
    string name, password, users, commands, id;

    id = getCurrentTimeAsString();
    cout << "Enter a user-readable name for the SuperKey: ";
    getline(cin, name);
    cout << "Enter a password for the SuperKey: ";
    getline(cin, password);
    cout << "Enter allowed users (comma-separated, * for all): ";
    getline(cin, users);
    cout << "Enter allowed commands (semicolon-separated, * for all): ";
    getline(cin, commands);

    string hash = generateSHA256(password);
    SuperKey sk{ id, name, hash, users, commands };
    superKeys[id] = sk;
    cout << "SuperKey added successfully with ID: " << id << "\n";
}

void editSuperKey(unordered_map<string, SuperKey>& superKeys) {
    string id;
    cout << "Enter the ID of the SuperKey to edit: ";
    getline(cin, id);

    auto it = superKeys.find(id);
    if (it != superKeys.end()) {
        cout << "Editing SuperKey: " << it->second.readableName << endl;
        cout << "Enter a new password (leave blank to keep the same): ";
        string password;
        getline(cin, password);
        if (!password.empty()) {
            it->second.superKeyHash = generateSHA256(password);
        }
        cout << "Enter new allowed users (comma-separated, * for all): ";
        getline(cin, it->second.allowedUsers);
        cout << "Enter new allowed commands (semicolon-separated, * for all): ";
        getline(cin, it->second.allowedCommands);
        cout << "SuperKey updated successfully.\n";
    } else {
        cout << "SuperKey ID not found.\n";
    }
}

void deleteSuperKey(unordered_map<string, SuperKey>& superKeys) {
    string id;
    cout << "Enter the ID of the SuperKey to delete: ";
    getline(cin, id);

    if (superKeys.find(id) != superKeys.end()) {
        superKeys.erase(id);
        cout << "SuperKey deleted successfully.\n";
    } else {
        cout << "SuperKey ID not found.\n";
    }
}

void menu() {
    unordered_map<string, SuperKey> superKeys = loadSuperKeys();

    string input;
    while (true) {
        cout << "SuperKey Editor Menu:\n";
        cout << "1. Add SuperKey\n";
        cout << "2. Edit SuperKey\n";
        cout << "3. Delete SuperKey\n";
        cout << "4. Exit\n";
        cout << "Choose an option: ";
        getline(cin, input);

        if (input == "1") {
            addSuperKey(superKeys);
        } else if (input == "2") {
            editSuperKey(superKeys);
        } else if (input == "3") {
            deleteSuperKey(superKeys);
        } else if (input == "4") {
            break;
        } else {
            cout << "Invalid option. Please try again.\n";
        }

        saveSuperKeys(superKeys);
    }
}

int main() {
    if (geteuid() != 0) {
        cout << "editosu can only be run as root.\n";
        return 1;
    }
    menu();
    return 0;
}