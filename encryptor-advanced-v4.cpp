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
#include <QMenu>

#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <cstring>
#include <cctype>
#include <filesystem>
#include <functional>
#include <algorithm> // For sorting

namespace fs = std::filesystem;

// --- OpenSSL Headers ---
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

// --- CONSTANTS ---
const size_t BUFFER_SIZE = 65536; 
const int AES_KEY_LEN = 32;       
const int AES_IV_LEN = 16;        
const int SALT_LEN = 16;

// --- UTILS ---
int charToInt(char c) { return c - '0'; }

// --- KEY DERIVATION ---
bool deriveKey(const std::string& pass, unsigned char* salt, unsigned char* key) {
    if (!PKCS5_PBKDF2_HMAC(pass.c_str(), pass.length(), salt, SALT_LEN, 10000, EVP_sha256(), AES_KEY_LEN, key))
        return false;
    return true;
}

// --- NAME ENCRYPTION (AES-256 + Base64) ---
QString encryptName(QString originalName, unsigned char* key) {
    std::string plain = originalName.toStdString();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[AES_IV_LEN] = {0}; 
    int outLen, finalLen;
    std::vector<unsigned char> outBuf(plain.size() + AES_BLOCK_SIZE);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, outBuf.data(), &outLen, (unsigned char*)plain.c_str(), plain.length());
    EVP_EncryptFinal_ex(ctx, outBuf.data() + outLen, &finalLen);
    EVP_CIPHER_CTX_free(ctx);
    
    QByteArray encryptedBytes(reinterpret_cast<char*>(outBuf.data()), outLen + finalLen);
    return QString(encryptedBytes.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

QString decryptName(QString encryptedBase64, unsigned char* key) {
    QByteArray encryptedBytes = QByteArray::fromBase64(encryptedBase64.toUtf8(), QByteArray::Base64UrlEncoding);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[AES_IV_LEN] = {0};
    int outLen, finalLen;
    std::vector<unsigned char> outBuf(encryptedBytes.size() + AES_BLOCK_SIZE);
    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, outBuf.data(), &outLen, (unsigned char*)encryptedBytes.data(), encryptedBytes.size());
    EVP_DecryptFinal_ex(ctx, outBuf.data() + outLen, &finalLen);
    EVP_CIPHER_CTX_free(ctx);
    
    std::string result((char*)outBuf.data(), outLen + finalLen);
    return QString::fromStdString(result);
}

// --- FILE PROCESSOR (AES-256) ---
void processFileAES(std::string inputPath, std::string outputPath, 
                    unsigned char* key, unsigned char* salt, bool encrypt, 
                    std::function<void(long long delta, long long fileTotal)> progressCallback) {
    
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

    unsigned char iv[AES_IV_LEN];
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    
    if (encrypt) {
        RAND_bytes(iv, AES_IV_LEN); 
        fwrite(salt, 1, SALT_LEN, outFile);
        fwrite(iv, 1, AES_IV_LEN, outFile);
    } else {
        unsigned char tempSalt[SALT_LEN];
        if (fread(tempSalt, 1, SALT_LEN, inFile) != SALT_LEN || 
            fread(iv, 1, AES_IV_LEN, inFile) != AES_IV_LEN) {
            fclose(inFile); fclose(outFile); EVP_CIPHER_CTX_free(ctx); return;
        }
        totalSize -= (SALT_LEN + AES_IV_LEN); 
    }

    if (encrypt) EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    else         EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);

    unsigned char inBuf[BUFFER_SIZE];
    unsigned char outBuf[BUFFER_SIZE + AES_BLOCK_SIZE]; 
    int outLen;

    while (true) {
        int bytesRead = fread(inBuf, 1, BUFFER_SIZE, inFile);
        if (bytesRead <= 0) break;

        if (encrypt) EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
        else         EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);

        fwrite(outBuf, 1, outLen, outFile);
        if(progressCallback) progressCallback(bytesRead, totalSize);
    }

    if (encrypt) EVP_EncryptFinal_ex(ctx, outBuf, &outLen);
    else         EVP_DecryptFinal_ex(ctx, outBuf, &outLen);
    
    fwrite(outBuf, 1, outLen, outFile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(inFile);
    fclose(outFile);
}

// --- FAST PROCESSOR ---
void processFileFast(std::string inputPath, std::string outputPath, std::string passcode, bool encrypt, 
                     std::function<void(long long delta, long long fileTotal)> progressCallback) {
    std::vector<int> passDigits;
    for (char c : passcode) {
        if (isdigit(static_cast<unsigned char>(c))) passDigits.push_back(charToInt(c));
    }
    if (passDigits.empty()) return; 

    FILE* inFile = fopen(inputPath.c_str(), "rb");
    FILE* outFile = fopen(outputPath.c_str(), "wb");
    if (!inFile || !outFile) { if(inFile) fclose(inFile); if(outFile) fclose(outFile); return; }

    fseek(inFile, 0, SEEK_END);
    long long totalSize = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    unsigned char buffer[BUFFER_SIZE];
    const int pssize = static_cast<int>(passDigits.size());
    int passIndex = 0;

    while (true) {
        size_t bytesRead = fread(buffer, 1, BUFFER_SIZE, inFile);
        if (bytesRead <= 0) break;

        for (size_t i = 0; i < bytesRead; ++i) {
            unsigned char byte = buffer[i];
            int high = (byte >> 4) & 0x0F;
            int d1 = passDigits[passIndex];
            passIndex = (passIndex + 1 < pssize) ? passIndex + 1 : 0; 
            high = encrypt ? (high + d1) % 16 : (high - d1 + 16) % 16;

            int low = byte & 0x0F;
            int d2 = passDigits[passIndex];
            passIndex = (passIndex + 1 < pssize) ? passIndex + 1 : 0;
            low = encrypt ? (low + d2) % 16 : (low - d2 + 16) % 16;

            buffer[i] = static_cast<unsigned char>((high << 4) | low);
        }

        fwrite(buffer, 1, bytesRead, outFile);
        if(progressCallback) progressCallback(bytesRead, totalSize);
    }
    fclose(inFile);
    fclose(outFile);
}

// --- BATCH MANAGER ---
void processBatch(std::string startPath, std::string passcode, bool encrypt, bool useAES, 
                  bool encryptFileNames, bool encryptFolderNames, bool deleteOriginal,
                  QProgressBar* barFile, QProgressBar* barTotal, QPushButton* btn, QWidget* parent) {
    
    std::vector<std::string> filesToProcess;
    std::vector<std::string> foldersToProcess; // NEW: Track folders
    long long totalBatchBytes = 0;

    // 1. DISCOVERY
    try {
        if (fs::is_directory(startPath)) {
            // Recursive walk
            for (const auto& entry : fs::recursive_directory_iterator(startPath)) {
                if (entry.is_regular_file()) {
                    filesToProcess.push_back(entry.path().string());
                    totalBatchBytes += entry.file_size();
                } else if (entry.is_directory()) {
                    foldersToProcess.push_back(entry.path().string());
                }
            }
            // Don't forget the root folder itself if we want to rename it (optional, usually safer to skip root)
            // foldersToProcess.push_back(startPath); 
        } else if (fs::exists(startPath)) {
            filesToProcess.push_back(startPath);
            totalBatchBytes = fs::file_size(startPath);
        }
    } catch (...) {
        QMetaObject::invokeMethod(parent, [=](){
            QMessageBox::warning(parent, "Error", "Invalid path.");
            btn->setEnabled(true); btn->setText("Start Operation");
        }, Qt::QueuedConnection);
        return;
    }

    if (filesToProcess.empty() && foldersToProcess.empty()) {
        QMetaObject::invokeMethod(parent, [=](){
            QMessageBox::warning(parent, "Error", "No files found.");
            btn->setEnabled(true); btn->setText("Start Operation");
        }, Qt::QueuedConnection);
        return;
    }

    // 2. PROCESS FILES FIRST (Paths are valid now)
    long long globalProcessed = 0;
    
    for (const auto& inPath : filesToProcess) {
        std::string outPath;
        unsigned char salt[SALT_LEN];
        unsigned char key[AES_KEY_LEN];

        if (encrypt) {
            RAND_bytes(salt, SALT_LEN); 
            deriveKey(passcode, salt, key);

            fs::path p(inPath);
            std::string parentDir = p.parent_path().string();
            std::string filename = p.filename().string();
            
            if (encryptFileNames && useAES) {
                QString qEncName = encryptName(QString::fromStdString(filename), key);
                outPath = parentDir + "/" + qEncName.toStdString() + ".aes";
            } else {
                outPath = inPath + (useAES ? ".aes" : ".enc");
            }

        } else {
            // Decrypt Logic
            if (useAES) {
                FILE* peekFile = fopen(inPath.c_str(), "rb");
                if (peekFile) {
                    if (fread(salt, 1, SALT_LEN, peekFile) != SALT_LEN) { fclose(peekFile); continue; }
                    fclose(peekFile);
                    deriveKey(passcode, salt, key);
                } else continue;
            }

            fs::path p(inPath);
            std::string parentDir = p.parent_path().string();
            std::string stem = p.stem().string();
            
            if (encryptFileNames && useAES) {
                 QString qDecName = decryptName(QString::fromStdString(stem), key);
                 outPath = parentDir + "/" + qDecName.toStdString();
            } else {
                 std::string suffix = useAES ? ".aes" : ".enc";
                 if (inPath.size() > suffix.size() && 
                     inPath.compare(inPath.size() - suffix.size(), suffix.size(), suffix) == 0) {
                     outPath = inPath.substr(0, inPath.size() - suffix.size());
                 } else {
                     continue; 
                 }
            }
        }

        long long localProcessed = 0;
        auto callback = [&](long long delta, long long fileTotal) {
            localProcessed += delta;
            globalProcessed += delta;
            int percentFile = (fileTotal > 0) ? (localProcessed * 100 / fileTotal) : 0;
            int percentTotal = (totalBatchBytes > 0) ? (globalProcessed * 100 / totalBatchBytes) : 0;
            QMetaObject::invokeMethod(parent, [=](){
                barFile->setValue(percentFile);
                barTotal->setValue(percentTotal);
            }, Qt::QueuedConnection);
        };

        if (useAES) processFileAES(inPath, outPath, key, salt, encrypt, callback);
        else        processFileFast(inPath, outPath, passcode, encrypt, callback);
        
        if (deleteOriginal) { try { fs::remove(inPath); } catch (...) {} }
    }

    // 3. PROCESS FOLDERS LAST (Bottom-Up Rename)
    // Only if AES and EncryptFolderNames are active
    if (encryptFolderNames && useAES && !foldersToProcess.empty()) {
        
        // Setup Fixed Salt for Folders (Cannot store salt in folder, so use deterministic hash)
        unsigned char folderSalt[SALT_LEN];
        SHA256((unsigned char*)passcode.c_str(), passcode.length(), folderSalt); // Salt is Hash of Pass
        // Truncate to 16 bytes (SHA256 is 32) - just use first 16
        
        unsigned char folderKey[AES_KEY_LEN];
        deriveKey(passcode, folderSalt, folderKey); // Derive Folder Key

        // SORT: Deepest paths first (Longest string length)
        // This prevents renaming a parent before its children
        std::sort(foldersToProcess.begin(), foldersToProcess.end(), [](const std::string& a, const std::string& b) {
            return a.length() > b.length();
        });

        for (const auto& dirPath : foldersToProcess) {
            fs::path p(dirPath);
            std::string parentDir = p.parent_path().string();
            std::string dirName = p.filename().string();
            std::string newPath;

            if (encrypt) {
                QString qEnc = encryptName(QString::fromStdString(dirName), folderKey);
                newPath = parentDir + "/" + qEnc.toStdString();
            } else {
                // Try decrypt
                // Simple heuristic: Is it valid Base64?
                // We just try decrypting. If it wasn't encrypted, result might be garbage, 
                // but that's the risk of "Folder Encryption" without metadata files.
                QString qDec = decryptName(QString::fromStdString(dirName), folderKey);
                // Basic check: If result is empty or garbage, maybe don't rename? 
                // For this code, we assume if mode is Decrypt, user expects it.
                if (!qDec.isEmpty()) {
                     newPath = parentDir + "/" + qDec.toStdString();
                } else {
                    continue; 
                }
            }

            try {
                fs::rename(dirPath, newPath);
            } catch (...) {
                // Ignore errors (e.g., folder locked by system)
            }
        }
    }

    // 4. FINISHED
    QMetaObject::invokeMethod(parent, [=](){
        btn->setEnabled(true);
        btn->setText("Start Operation");
        barFile->setValue(100);
        barTotal->setValue(100);
        QMessageBox::information(parent, "Success", "Operation Complete!");
        barFile->setValue(0);
        barTotal->setValue(0);
    }, Qt::QueuedConnection);
}

// --- UI CLASS ---
class EncryptorWindow : public QWidget {
public:
    QLineEdit *pathEdit;
    QLineEdit *passEdit;
    QProgressBar *progressBarFile;  
    QProgressBar *progressBarTotal; 
    QRadioButton *radioEncrypt;
    QCheckBox *checkAES;
    QCheckBox *checkEncryptNames;
    QCheckBox *checkEncryptFolders;
    QCheckBox *checkDeleteOriginal;
    QPushButton *btnRun;
    
    EncryptorWindow() {
        setWindowTitle("Pro Encryptor (Full Recursive)");
        resize(550, 550);
        QFont font = this->font(); font.setPointSize(10); this->setFont(font);

        QVBoxLayout *mainLayout = new QVBoxLayout(this);
        mainLayout->setContentsMargins(25, 25, 25, 25);
        mainLayout->setSpacing(15);

        // --- FILE SELECTION ---
        mainLayout->addWidget(new QLabel("Select Input:"));
        QHBoxLayout *pathLayout = new QHBoxLayout();
        pathEdit = new QLineEdit(); 
        pathEdit->setPlaceholderText("Path...");
        pathLayout->addWidget(pathEdit);
        
        QPushButton *btnFile = new QPushButton("File...");
        pathLayout->addWidget(btnFile);
        QPushButton *btnFolder = new QPushButton("Folder...");
        pathLayout->addWidget(btnFolder);
        mainLayout->addLayout(pathLayout);

        connect(btnFile, &QPushButton::clicked, [this]() {
            pathEdit->setText(QFileDialog::getOpenFileName(this, "Select File"));
        });
        connect(btnFolder, &QPushButton::clicked, [this]() {
            pathEdit->setText(QFileDialog::getExistingDirectory(this, "Select Folder"));
        });

        // --- PASSCODE ---
        mainLayout->addWidget(new QLabel("Passcode:"));
        passEdit = new QLineEdit(); passEdit->setEchoMode(QLineEdit::Password);
        mainLayout->addWidget(passEdit);

        // --- SETTINGS ---
        QGroupBox *gb = new QGroupBox("Configuration");
        QVBoxLayout *gbLayout = new QVBoxLayout;
        
        QHBoxLayout *modeLayout = new QHBoxLayout;
        radioEncrypt = new QRadioButton("Encrypt");
        QRadioButton *radioDecrypt = new QRadioButton("Decrypt");
        radioEncrypt->setChecked(true);
        modeLayout->addWidget(radioEncrypt);
        modeLayout->addWidget(radioDecrypt);
        gbLayout->addLayout(modeLayout);

        checkAES = new QCheckBox("Use AES-256 (Required for Name Encryption)");
        checkAES->setChecked(true);
        gbLayout->addWidget(checkAES);
        
        checkEncryptNames = new QCheckBox("Encrypt/Decrypt File Names");
        checkEncryptNames->setChecked(true);
        gbLayout->addWidget(checkEncryptNames);

        checkEncryptFolders = new QCheckBox("Encrypt/Decrypt Folder Names");
        checkEncryptFolders->setChecked(true);
        gbLayout->addWidget(checkEncryptFolders);

        checkDeleteOriginal = new QCheckBox("Delete original files");
        checkDeleteOriginal->setStyleSheet("color: red;");
        checkDeleteOriginal->setChecked(false);
        gbLayout->addWidget(checkDeleteOriginal);

        gb->setLayout(gbLayout);
        mainLayout->addWidget(gb);

        connect(checkAES, &QCheckBox::toggled, [this](bool checked){
            checkEncryptNames->setEnabled(checked);
            checkEncryptFolders->setEnabled(checked);
            if(!checked) {
                checkEncryptNames->setChecked(false);
                checkEncryptFolders->setChecked(false);
            }
        });

        // --- PROGRESS ---
        mainLayout->addWidget(new QLabel("Current File:"));
        progressBarFile = new QProgressBar();
        progressBarFile->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(progressBarFile);

        mainLayout->addWidget(new QLabel("Total Batch:"));
        progressBarTotal = new QProgressBar();
        progressBarTotal->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(progressBarTotal);

        // --- RUN ---
        btnRun = new QPushButton("Start Operation");
        btnRun->setFixedHeight(45);
        btnRun->setStyleSheet("QPushButton { background-color: #007bff; color: white; font-weight: bold; border-radius: 4px; } QPushButton:hover { background-color: #0056b3; }");
        mainLayout->addWidget(btnRun);

        connect(btnRun, &QPushButton::clicked, [this]() {
            std::string path = pathEdit->text().toStdString();
            std::string pass = passEdit->text().toStdString();
            bool encrypt = radioEncrypt->isChecked();
            bool useAES = checkAES->isChecked();
            bool encNames = checkEncryptNames->isChecked();
            bool encFolders = checkEncryptFolders->isChecked();
            bool delOrig = checkDeleteOriginal->isChecked();

            if (path.empty() || pass.empty()) {
                QMessageBox::warning(this, "Error", "Invalid inputs."); return;
            }
            if (!fs::exists(path)) {
                QMessageBox::warning(this, "Error", "Path not found."); return;
            }
            if (delOrig && QMessageBox::question(this, "Confirm", "Delete originals?", QMessageBox::Yes|QMessageBox::No) == QMessageBox::No) return;

            btnRun->setEnabled(false);
            btnRun->setText("Processing...");
            progressBarFile->setValue(0);
            progressBarTotal->setValue(0);

            std::thread worker(processBatch, path, pass, encrypt, useAES, encNames, encFolders, delOrig, progressBarFile, progressBarTotal, btnRun, this);
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