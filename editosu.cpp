#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <ctime>
#include <sstream>
#include <vector>
#include <unistd.h>
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
    int id; // Changed to int cause its an ID
    string readableName;
    string superKeyHash;
    string allowedUsers;
    string allowedCommands;
};

pair<unordered_map<int, SuperKey>, int> loadSuperKeys() {
    unordered_map<int, SuperKey> superKeys;
    ifstream inFile(SUPERKEY_FILE);
    string line;
    int maxId = -1;

    while (getline(inFile, line)) {
        stringstream ss(line);
        string segment;
        vector<string> seglist;

        while (getline(ss, segment, ':')) {
            seglist.push_back(segment);
        }

        if (seglist.size() < 5) continue;

        int id = stoi(seglist[0]);
        maxId = max(maxId, id);
        SuperKey sk{ id, seglist[1], seglist[2], seglist[3], seglist[4] };
        superKeys[id] = sk;
    }

    inFile.close();
    return { superKeys, maxId };
}

void saveSuperKeys(const unordered_map<int, SuperKey>& superKeys) {
    ofstream outFile(SUPERKEY_FILE);
    for (const auto& pair : superKeys) {
        const auto& sk = pair.second;
        outFile << sk.id << ":" << sk.readableName << ":" << sk.superKeyHash << ":" << sk.allowedUsers << ":" << sk.allowedCommands << endl;
    }
    outFile.close();
}

void addSuperKey(unordered_map<int, SuperKey>& superKeys, int& currentMaxId) {
    string name, password, users, commands;

    int id = ++currentMaxId;  // Increment currentMaxId for new ID
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

void editSuperKey(unordered_map<int, SuperKey>& superKeys) {
    int id;
    cout << "Enter the ID of the SuperKey to edit: ";
    cin >> id;
    cin.ignore();  // Eat the newline character left in the input buffer

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

void deleteSuperKey(unordered_map<int, SuperKey>& superKeys) {
    int id;
    cout << "Enter the ID of the SuperKey to delete: ";
    cin >> id;
    cin.ignore(); // Eat the newline character

    if (superKeys.find(id) != superKeys.end()) {
        superKeys.erase(id);
        cout << "SuperKey deleted successfully.\n";
    } else {
        cout << "SuperKey ID not found.\n";
    }
}

void listSuperKeys(const unordered_map<int, SuperKey>& superKeys) {
    cout << "Listing all SuperKeys:\n";
    for (const auto& pair : superKeys) {
        const auto& sk = pair.second;
        cout << "ID: " << sk.id << ", Name: " << sk.readableName << ", Allowed Users: " << sk.allowedUsers << ", Allowed Commands: " << sk.allowedCommands << endl;
    }
}

void menu() {
    auto [superKeys, currentMaxId] = loadSuperKeys();

    string input;
    while (true) {
        cout << "SuperKey Editor Menu:\n";
        cout << "1. Add SuperKey\n";
        cout << "2. Edit SuperKey\n";
        cout << "3. Delete SuperKey\n";
        cout << "4. List SuperKeys\n";
        cout << "5. Exit\n";
        cout << "Choose an option: ";
        getline(cin, input);

        if (input == "1") {
            addSuperKey(superKeys, currentMaxId);
        } else if (input == "2") {
            editSuperKey(superKeys);
        } else if (input == "3") {
            deleteSuperKey(superKeys);
        } else if (input == "4") {
            listSuperKeys(superKeys);
        } else if (input == "5") {
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
