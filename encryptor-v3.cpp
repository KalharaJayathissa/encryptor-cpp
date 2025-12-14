#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cctype>
#include <cstdio>

using namespace std;

// Buffer Size: 64KB (High Speed)
const size_t BUFFER_SIZE = 65536; 

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

    ifstream inFile(inputPath, ios::binary);
    if (!inFile) {
        cerr << "Error: Could not open input file." << endl;
        return;
    }

    // Get Total Size for Progress Bar
    inFile.seekg(0, ios::end);
    long long totalSize = inFile.tellg();
    inFile.seekg(0, ios::beg);

    ofstream outFile(outputPath, ios::binary);
    if (!outFile) {
        cerr << "Error: Could not create output file." << endl;
        return;
    }

    // Buffer Setup
    vector<char> buffer(BUFFER_SIZE); 
    
    int pssize = passDigits.size();
    int passIndex = 0; 
    long long processedBytes = 0;

    cout << (encrypt ? "Encrypting: " : "Decrypting: ") << inputPath << endl;

    // --- MAIN PROCESSING LOOP ---
    while (inFile) {
        // 1. Read Chunk
        inFile.read(buffer.data(), BUFFER_SIZE);
        long bytesRead = inFile.gcount();
        if (bytesRead == 0) break; 

        // 2. Process Chunk in RAM
        for (long i = 0; i < bytesRead; ++i) {
            unsigned char byte = static_cast<unsigned char>(buffer[i]);
            
            // Logic: High Nibble
            int high = (byte >> 4) & 0x0F;
            int d1 = passDigits[passIndex];
            passIndex++;
            if (passIndex >= pssize) passIndex = 0;
            
            high = encrypt ? (high + d1) % 16 : (high - d1 + 16) % 16;

            // Logic: Low Nibble
            int low = byte & 0x0F;
            int d2 = passDigits[passIndex];
            passIndex++;
            if (passIndex >= pssize) passIndex = 0;

            low = encrypt ? (low + d2) % 16 : (low - d2 + 16) % 16;

            // Store back in buffer
            buffer[i] = static_cast<char>((high << 4) | low);
        }

        // 3. Write Chunk
        outFile.write(buffer.data(), bytesRead);

        // 4. Update Progress Bar
        processedBytes += bytesRead;
        if (totalSize > 0) {
            int percent = (processedBytes * 100) / totalSize;
            
            // \r = Carriage Return (Overwrite line)
            cout << "\rProgress: [";
            
            // Calculate number of '=' signs (Bar width: 50 chars)
            int pos = 50 * percent / 100;
            for (int i = 0; i < 50; ++i) {
                if (i < pos) cout << "=";
                else if (i == pos) cout << ">";
                else cout << " ";
            }
            cout << "] " << percent << "% " << flush;
        }
    }

    cout << endl << "Done! Output saved to: " << outputPath << endl;
    inFile.close();
    outFile.close();
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        cout << "Usage: ./encryptor-fast <mode> <filename> <passcode>" << endl;
        return 1;
    }

    string mode = argv[1];
    string filename = argv[2];
    string passcode = argv[3];

    // Check Input Exists
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
        return 1;
    }

    return 0;
}