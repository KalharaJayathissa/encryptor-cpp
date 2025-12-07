#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cctype>
#include <cstdio>

using namespace std;

int charToInt(char c) {
    return c - '0';
}

void processFile(const string& inputPath, const string& outputPath, const string& passcode, bool encrypt) {
    vector<int> passDigits;
    for (char c : passcode) {
        if (isdigit(c)) passDigits.push_back(charToInt(c));
    }

    if (passDigits.empty()) {
        cerr << "Error: Passcode must contain digits!" << endl;
        return;
    }

    // 1. Open Input File
    ifstream inFile(inputPath, ios::binary);
    if (!inFile) {
        cerr << "Error: Could not open input file." << endl;
        return;
    }

    // --- NEW: Get Total File Size for Percentage ---
    inFile.seekg(0, ios::end);      // Jump to the end
    long long totalSize = inFile.tellg(); // Check position (size)
    inFile.seekg(0, ios::beg);      // Jump back to start
    // -----------------------------------------------

    ofstream outFile(outputPath, ios::binary);
    if (!outFile) {
        cerr << "Error: Could not create output file." << endl;
        return;
    }

    char byteBuffer;
    int passIndex = 0; 
    long long currentByte = 0; // Track how many bytes we processed

    cout << (encrypt ? "Encrypting: " : "Decrypting: ") << inputPath << endl;

    while (inFile.get(byteBuffer)) {
        unsigned char byte = static_cast<unsigned char>(byteBuffer);
        int highNibble = (byte >> 4) & 0x0F;
        int lowNibble = byte & 0x0F;

        int digit1 = passDigits[passIndex % passDigits.size()];
        passIndex++;
        if (encrypt) highNibble = (highNibble + digit1) % 16;
        else         highNibble = (highNibble - digit1 + 16) % 16;

        int digit2 = passDigits[passIndex % passDigits.size()];
        passIndex++; 
        if (encrypt) lowNibble = (lowNibble + digit2) % 16;
        else         lowNibble = (lowNibble - digit2 + 16) % 16;

        unsigned char newByte = (highNibble << 4) | lowNibble;
        outFile.put(static_cast<char>(newByte));

        // --- NEW: Progress Bar Logic ---
        currentByte++;

        // Only update screen every 4096 bytes (4KB) or at the very end
        // This prevents the program from slowing down.
        if (currentByte % 4096 == 0 || currentByte == totalSize) {
            int percent = (currentByte * 100) / totalSize;
            
            // \r moves cursor to start of line
            cout << "\rProgress: ["; 
            
            // Draw the bar (50 chars wide)
            int pos = 50 * percent / 100;
            for (int i = 0; i < 50; ++i) {
                if (i < pos) cout << "=";
                else if (i == pos) cout << ">";
                else cout << " ";
            }
            cout << "] " << percent << "% " << flush; // flush forces print immediately
        }
        // -------------------------------
    }

    cout << endl << "Done! Output saved to: " << outputPath << endl;
    inFile.close();
    outFile.close();
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cout << "Usage: ./encryptor5 <mode> <filename> <passcode>" << endl;
        return 1;
    }

    string mode = argv[1];
    string filename = argv[2];
    string passcode = argv[3];

    ifstream checkFile(filename);
    if (!checkFile) { 
        cerr << "Error: Input file '" << filename << "' does not exist." << endl;
        return 1;
    }
    checkFile.close(); 

    if (mode == "e") {
        string outName = filename + ".enc";
        processFile(filename, outName, passcode, true);
    } 
    else if (mode == "d") {
        string outName = "decrypted_" + filename;
        if (filename.size() > 4 && filename.substr(filename.size() - 4) == ".enc") {
             outName = "decrypted_" + filename.substr(0, filename.size() - 4);
        }
        processFile(filename, outName, passcode, false);
    } 
    else {
        cout << "Invalid mode. Use 'e' or 'd'." << endl;
    }

    return 0;
}