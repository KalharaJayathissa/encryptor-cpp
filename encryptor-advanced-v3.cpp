#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QFileDialog>
#include <QProgressBar>
#include <QLabel>
#include <QMessageBox>
#include <QRadioButton>
#include <QCheckBox>
#include <QGroupBox>
#include <QStyleFactory>
#include <QFont>

#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <cstring>
#include <cctype>
#include <filesystem>
#include <functional>

// Use simpler namespace for filesystem
namespace fs = std::filesystem;

// --- OpenSSL Headers ---
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

// --- CONSTANTS ---
const size_t BUFFER_SIZE = 65536; // 64KB
const int AES_KEY_LEN = 32;       // 256 bits
const int AES_IV_LEN = 16;        // 128 bits
const int SALT_LEN = 16;

// --- UTILS ---
int charToInt(char c) { return c - '0'; }

// --- CORE: KEY DERIVATION ---
bool deriveKey(const std::string& pass, unsigned char* salt, unsigned char* key) {
    // PBKDF2: 10,000 iterations to generate a 32-byte key from text + salt
    if (!PKCS5_PBKDF2_HMAC(pass.c_str(), pass.length(), salt, SALT_LEN, 10000, EVP_sha256(), AES_KEY_LEN, key))
        return false;
    return true;
}

// --- CORE: AES-256 (With Callback) ---
// Note: This function knows NOTHING about the UI. It just does work and reports progress.
void processFileAES(std::string inputPath, std::string outputPath, std::string passcode, bool encrypt, 
                    std::function<void(long long delta, long long fileTotal)> progressCallback) {
    
    FILE* inFile = fopen(inputPath.c_str(), "rb");
    FILE* outFile = fopen(outputPath.c_str(), "wb");

    if (!inFile || !outFile) {
        if(inFile) fclose(inFile);
        if(outFile) fclose(outFile);
        return;
    }

    // Get File Size
    fseek(inFile, 0, SEEK_END);
    long long totalSize = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    unsigned char key[AES_KEY_LEN];
    unsigned char iv[AES_IV_LEN];
    unsigned char salt[SALT_LEN];

    // Encryption Setup
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    
    if (encrypt) {
        RAND_bytes(salt, SALT_LEN);
        RAND_bytes(iv, AES_IV_LEN); // Random IV for security
        fwrite(salt, 1, SALT_LEN, outFile);
        fwrite(iv, 1, AES_IV_LEN, outFile);
    } else {
        if (fread(salt, 1, SALT_LEN, inFile) != SALT_LEN || 
            fread(iv, 1, AES_IV_LEN, inFile) != AES_IV_LEN) {
            fclose(inFile); fclose(outFile); EVP_CIPHER_CTX_free(ctx); return;
        }
        totalSize -= (SALT_LEN + AES_IV_LEN);
    }

    deriveKey(passcode, salt, key);

    if (encrypt) EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    else         EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);

    // Processing Loop
    unsigned char inBuf[BUFFER_SIZE];
    unsigned char outBuf[BUFFER_SIZE + AES_BLOCK_SIZE]; 
    int outLen;

    while (true) {
        int bytesRead = fread(inBuf, 1, BUFFER_SIZE, inFile);
        if (bytesRead <= 0) break;

        if (encrypt) EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
        else         EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);

        fwrite(outBuf, 1, outLen, outFile);
        
        // REPORT PROGRESS: Send "bytesRead" (delta) to the manager
        if(progressCallback) progressCallback(bytesRead, totalSize);
    }

    if (encrypt) EVP_EncryptFinal_ex(ctx, outBuf, &outLen);
    else         EVP_DecryptFinal_ex(ctx, outBuf, &outLen);
    
    fwrite(outBuf, 1, outLen, outFile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(inFile);
    fclose(outFile);
}

// --- CORE: FAST METHOD (With Callback) ---
void processFileFast(std::string inputPath, std::string outputPath, std::string passcode, bool encrypt, 
                     std::function<void(long long delta, long long fileTotal)> progressCallback) {
    
    // Prepare password math
    std::vector<int> passDigits;
    for (char c : passcode) {
        if (isdigit(static_cast<unsigned char>(c))) passDigits.push_back(charToInt(c));
    }
    if (passDigits.empty()) return; // Should be checked by UI before calling

    FILE* inFile = fopen(inputPath.c_str(), "rb");
    FILE* outFile = fopen(outputPath.c_str(), "wb");
    if (!inFile || !outFile) {
        if(inFile) fclose(inFile);
        if(outFile) fclose(outFile);
        return;
    }

    fseek(inFile, 0, SEEK_END);
    long long totalSize = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    unsigned char buffer[BUFFER_SIZE];
    const int pssize = static_cast<int>(passDigits.size());
    int passIndex = 0;

    while (true) {
        size_t bytesRead = fread(buffer, 1, BUFFER_SIZE, inFile);
        if (bytesRead <= 0) break;

        // In-memory obfuscation
        for (size_t i = 0; i < bytesRead; ++i) {
            unsigned char byte = buffer[i];
            
            // High Nibble
            int high = (byte >> 4) & 0x0F;
            int d1 = passDigits[passIndex];
            passIndex = (passIndex + 1 < pssize) ? passIndex + 1 : 0; // Fast modulo
            high = encrypt ? (high + d1) % 16 : (high - d1 + 16) % 16;

            // Low Nibble
            int low = byte & 0x0F;
            int d2 = passDigits[passIndex];
            passIndex = (passIndex + 1 < pssize) ? passIndex + 1 : 0;
            low = encrypt ? (low + d2) % 16 : (low - d2 + 16) % 16;

            buffer[i] = static_cast<unsigned char>((high << 4) | low);
        }

        fwrite(buffer, 1, bytesRead, outFile);

        // REPORT PROGRESS
        if(progressCallback) progressCallback(bytesRead, totalSize);
    }

    fclose(inFile);
    fclose(outFile);
}

// --- LOGIC: BATCH MANAGER (Auto-detects File vs Folder) ---
void processBatch(std::string startPath, std::string passcode, bool encrypt, bool useAES,
                  QProgressBar* barFile, QProgressBar* barTotal, QPushButton* btn, QWidget* parent) {
    
    std::vector<std::string> filesToProcess;
    long long totalBatchBytes = 0;

    // 1. DISCOVERY: Auto-detect File vs Folder
    try {
        if (fs::is_directory(startPath)) {
            // Recursive walk
            for (const auto& entry : fs::recursive_directory_iterator(startPath)) {
                if (entry.is_regular_file()) {
                    filesToProcess.push_back(entry.path().string());
                    totalBatchBytes += entry.file_size();
                }
            }
        } else if (fs::exists(startPath)) {
            // Single file
            filesToProcess.push_back(startPath);
            totalBatchBytes = fs::file_size(startPath);
        }
    } catch (...) {
        QMetaObject::invokeMethod(parent, [=](){
            QMessageBox::warning(parent, "Error", "Invalid path or permission denied.");
            btn->setEnabled(true); btn->setText("Start Operation");
        }, Qt::QueuedConnection);
        return;
    }

    if (filesToProcess.empty()) {
        QMetaObject::invokeMethod(parent, [=](){
            QMessageBox::warning(parent, "Error", "No files found to process.");
            btn->setEnabled(true); btn->setText("Start Operation");
        }, Qt::QueuedConnection);
        return;
    }

    // 2. PROCESSING
    long long globalProcessed = 0;
    
    for (const auto& inPath : filesToProcess) {
        // --- Naming Logic ---
        std::string outPath;
        if (encrypt) {
            outPath = inPath + (useAES ? ".aes" : ".enc");
        } else {
            // Check if file ends with correct extension
            std::string suffix = useAES ? ".aes" : ".enc";
            if (inPath.size() > suffix.size() && 
                inPath.compare(inPath.size() - suffix.size(), suffix.size(), suffix) == 0) {
                outPath = inPath.substr(0, inPath.size() - suffix.size());
            } else {
                continue; // Skip files that don't look encrypted
            }
        }

        // --- Callback Definition ---
        // This runs THOUSANDS of times per second. Logic must be fast.
        // We track local bytes for 'File Bar' and global bytes for 'Total Bar'
        long long localProcessed = 0;
        
        auto callback = [&](long long delta, long long fileTotal) {
            localProcessed += delta;
            globalProcessed += delta;

            // Only update UI every 1% change or so to prevent freezing (optional logic)
            // For simplicity, we send updates but use QueuedConnection which handles buffering.
            
            int percentFile = (fileTotal > 0) ? (localProcessed * 100 / fileTotal) : 0;
            int percentTotal = (totalBatchBytes > 0) ? (globalProcessed * 100 / totalBatchBytes) : 0;

            QMetaObject::invokeMethod(parent, [=](){
                barFile->setValue(percentFile);
                barTotal->setValue(percentTotal);
            }, Qt::QueuedConnection);
        };

        // --- Run Algorithm ---
        if (useAES) processFileAES(inPath, outPath, passcode, encrypt, callback);
        else        processFileFast(inPath, outPath, passcode, encrypt, callback);
    }

    // 3. COMPLETION
    QMetaObject::invokeMethod(parent, [=](){
        btn->setEnabled(true);
        btn->setText("Start Operation");
        barFile->setValue(100);
        barTotal->setValue(100);
        QMessageBox::information(parent, "Success", "Operation Complete!");
        // Reset bars after user clicks OK
        barFile->setValue(0);
        barTotal->setValue(0);
    }, Qt::QueuedConnection);
}

// --- UI CLASS ---
class EncryptorWindow : public QWidget {
public:
    QLineEdit *pathEdit;
    QLineEdit *passEdit;
    QProgressBar *progressBarFile;  // Bar 1: Current File
    QProgressBar *progressBarTotal; // Bar 2: Total Batch
    QRadioButton *radioEncrypt;
    QCheckBox *checkAES;
    QPushButton *btnRun;
    
    EncryptorWindow() {
        setWindowTitle("Pro Encryptor (Batch Support)");
        resize(500, 450); // Make window slightly larger
        QFont font = this->font(); font.setPointSize(10); this->setFont(font);

        QVBoxLayout *mainLayout = new QVBoxLayout(this);
        mainLayout->setContentsMargins(25, 25, 25, 25);
        mainLayout->setSpacing(15);

        // --- FILE SELECTION BLOCK ---
        mainLayout->addWidget(new QLabel("Select Input (File or Folder):"));
        QHBoxLayout *pathLayout = new QHBoxLayout();
        pathEdit = new QLineEdit(); 
        pathEdit->setPlaceholderText("Path to file or folder...");
        pathLayout->addWidget(pathEdit);
        
        // Two buttons for easier selection logic
        QPushButton *btnFile = new QPushButton("File...");
        QPushButton *btnFolder = new QPushButton("Folder...");
        pathLayout->addWidget(btnFile);
        pathLayout->addWidget(btnFolder);
        mainLayout->addLayout(pathLayout);

        // Connect File Browse
        connect(btnFile, &QPushButton::clicked, [this]() {
            QString f = QFileDialog::getOpenFileName(this, "Select Single File");
            if(!f.isEmpty()) pathEdit->setText(f);
        });

        // Connect Folder Browse
        connect(btnFolder, &QPushButton::clicked, [this]() {
            QString d = QFileDialog::getExistingDirectory(this, "Select Folder to Encrypt Recursively");
            if(!d.isEmpty()) pathEdit->setText(d);
        });

        // --- PASSCODE BLOCK ---
        mainLayout->addWidget(new QLabel("Passcode:"));
        passEdit = new QLineEdit(); passEdit->setEchoMode(QLineEdit::Password);
        mainLayout->addWidget(passEdit);

        // --- SETTINGS BLOCK ---
        QGroupBox *gb = new QGroupBox("Configuration");
        QVBoxLayout *gbLayout = new QVBoxLayout;
        
        QHBoxLayout *modeLayout = new QHBoxLayout;
        radioEncrypt = new QRadioButton("Encrypt");
        QRadioButton *radioDecrypt = new QRadioButton("Decrypt");
        radioEncrypt->setChecked(true);
        modeLayout->addWidget(radioEncrypt);
        modeLayout->addWidget(radioDecrypt);
        gbLayout->addLayout(modeLayout);

        checkAES = new QCheckBox("Use AES-256 (Recommended)");
        checkAES->setChecked(true);
        gbLayout->addWidget(checkAES);

        gb->setLayout(gbLayout);
        mainLayout->addWidget(gb);

        // --- DUAL PROGRESS BARS ---
        mainLayout->addWidget(new QLabel("Current File Progress:"));
        progressBarFile = new QProgressBar();
        progressBarFile->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(progressBarFile);

        mainLayout->addWidget(new QLabel("Total Batch Progress:"));
        progressBarTotal = new QProgressBar();
        progressBarTotal->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(progressBarTotal);

        // --- RUN BUTTON ---
        btnRun = new QPushButton("Start Operation");
        btnRun->setFixedHeight(45);
        btnRun->setStyleSheet("QPushButton { background-color: #007bff; color: white; font-weight: bold; border-radius: 4px; } QPushButton:hover { background-color: #0056b3; }");
        mainLayout->addWidget(btnRun);

        // --- EXECUTION LOGIC ---
        connect(btnRun, &QPushButton::clicked, [this]() {
            std::string path = pathEdit->text().toStdString();
            std::string pass = passEdit->text().toStdString();
            bool encrypt = radioEncrypt->isChecked();
            bool useAES = checkAES->isChecked();

            // Validation
            if (path.empty() || pass.empty()) {
                QMessageBox::warning(this, "Error", "Please select a path and enter a password.");
                return;
            }
            if (!fs::exists(path)) {
                QMessageBox::warning(this, "Error", "The selected path does not exist.");
                return;
            }

            // Lock UI
            btnRun->setEnabled(false);
            btnRun->setText("Processing...");
            progressBarFile->setValue(0);
            progressBarTotal->setValue(0);

            // Start Thread (ProcessBatch handles everything)
            std::thread worker(processBatch, path, pass, encrypt, useAES, progressBarFile, progressBarTotal, btnRun, this);
            worker.detach();
        });
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    QApplication::setStyle(QStyleFactory::create("Fusion"));
    EncryptorWindow window;
    window.show();
    return app.exec();
}