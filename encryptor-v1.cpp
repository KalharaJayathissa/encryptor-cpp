#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cctype> // For isdigit

using namespace std;

// Helper to convert char digit to int (e.g., '5' -> 5)
int charToInt(char c) {
    return c - '0';
}

void processFile(const string& inputPath, const string& outputPath, const string& passcode, bool encrypt) {
    // 1. Prepare Passcode Digits
    vector<int> passDigits;
    for (char c : passcode) {
        if (isdigit(c)) {
            passDigits.push_back(charToInt(c));
        }
    }

    if (passDigits.empty()) {
        cerr << "Error: Passcode must contain digits!" << endl;
        return;
    }

    // 2. Open Files in Binary Mode
    ifstream inFile(inputPath, ios::binary);
    ofstream outFile(outputPath, ios::binary);

    if (!inFile || !outFile) {
        cerr << "Error: Could not open files." << endl;
        return;
    }

    char byteBuffer;
    int passIndex = 0; // To track which digit of the passcode we are using

    cout << (encrypt ? "Encrypting..." : "Decrypting...") << endl;

    // 3. Read byte by byte
    while (inFile.get(byteBuffer)) {
        // Convert char to unsigned char to avoid negative issues during bitwise ops
        unsigned char byte = static_cast<unsigned char>(byteBuffer);

        // --- SPLIT INTO NIBBLES ---
        // High nibble: Shift right 4 bits (e.g., 10110011 -> 00001011)
        int highNibble = (byte >> 4) & 0x0F;
        // Low nibble: Mask with 00001111 (0x0F)
        int lowNibble = byte & 0x0F;

        // --- PROCESS HIGH NIBBLE ---
        int digit1 = passDigits[passIndex % passDigits.size()];
        passIndex++; // Move to next digit
        
        if (encrypt) {
            // Add digit, wrap around 16
            highNibble = (highNibble + digit1) % 16;
        } else {
            // Subtract digit, handle negative wrap by adding 16
            highNibble = (highNibble - digit1 + 16) % 16;
        }

        // --- PROCESS LOW NIBBLE ---
        int digit2 = passDigits[passIndex % passDigits.size()];
        passIndex++; 

        if (encrypt) {
            lowNibble = (lowNibble + digit2) % 16;
        } else {
            lowNibble = (lowNibble - digit2 + 16) % 16;
        }

        // --- RECOMBINE ---
        // Shift high nibble back to left, OR it with low nibble
        unsigned char newByte = (highNibble << 4) | lowNibble;

        // Write to output file
        outFile.put(static_cast<char>(newByte));
    }

    cout << "Done! Saved to: " << outputPath << endl;
    inFile.close();
    outFile.close();
}

int main(int argc, char* argv[]) {
    // Basic argument parsing
    if (argc != 4) {
        cout << "Usage: ./img_crypto <mode> <filename> <passcode>" << endl;
        cout << "Mode: 'e' for encrypt, 'd' for decrypt" << endl;
        return 1;
    }

    string mode = argv[1];
    string filename = argv[2];
    string passcode = argv[3];

    if (mode == "e") {
        string outName = filename + ".enc";
        processFile(filename, outName, passcode, true);
    } 
    else if (mode == "d") {
        // If filename ends in .enc, remove it for the output
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