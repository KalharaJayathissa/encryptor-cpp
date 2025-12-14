#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
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

// --- OpenSSL Headers ---
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

// --- CONSTANTS ---
const size_t BUFFER_SIZE = 65536;
const int AES_KEY_LEN = 32; // 256 bits
const int AES_IV_LEN = 16;  // 128 bits
const int SALT_LEN = 16;

// --- UTILS ---
int charToInt(char c) { return c - '0'; }

// Derive 32-byte Key and 16-byte IV from string Password + Salt
bool deriveKey(const std::string& pass, unsigned char* salt, unsigned char* key, unsigned char* iv) {
    // PBKDF2 with SHA-256, 10000 iterations
    if (!PKCS5_PBKDF2_HMAC(pass.c_str(), pass.length(), salt, SALT_LEN, 10000, EVP_sha256(), AES_KEY_LEN, key))
        return false;
    
    // We need an IV. For this simple example, we'll derive it from the Key (simple hash)
    // In production, you might generate a separate random IV and store it with the salt.
    // Here we just hash the key to get a deterministic IV for this session.
    SHA256(key, AES_KEY_LEN, iv); // This gives 32 bytes, we only need first 16 for IV
    return true;
}

// --- LOGIC: AES-256 ---
void processFileAES(std::string inputPath, std::string outputPath, std::string passcode, bool encrypt, 
                    QProgressBar* bar, QPushButton* btn, QWidget* parent) {
    
    FILE* inFile = fopen(inputPath.c_str(), "rb");
    FILE* outFile = fopen(outputPath.c_str(), "wb");

    if (!inFile || !outFile) return;

    // Get Total Size
    fseek(inFile, 0, SEEK_END);
    long long totalSize = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    unsigned char key[AES_KEY_LEN];
    unsigned char iv[SHA256_DIGEST_LENGTH]; // Buffer large enough for SHA256 output
    unsigned char salt[SALT_LEN];

    // --- SETUP ENCRYPTION CONTEXT ---
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER* cipher = EVP_aes_256_cbc();
    
    if (encrypt) {
        // 1. Generate Random Salt
        RAND_bytes(salt, SALT_LEN);
        // 2. Write Salt to beginning of output file
        fwrite(salt, 1, SALT_LEN, outFile);
    } else {
        // 1. Read Salt from beginning of input file
        if (fread(salt, 1, SALT_LEN, inFile) != SALT_LEN) {
            fclose(inFile); fclose(outFile); EVP_CIPHER_CTX_free(ctx); return;
        }
        totalSize -= SALT_LEN; // Adjust progress bar math
    }

    // 3. Generate Key/IV
    deriveKey(passcode, salt, key, iv);

    // 4. Init OpenSSL
    if (encrypt) EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
    else         EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);

    // --- PROCESS LOOP ---
    unsigned char inBuf[BUFFER_SIZE];
    unsigned char outBuf[BUFFER_SIZE + AES_BLOCK_SIZE]; // Output can be slightly larger due to padding
    int outLen;
    long long processedBytes = 0;
    int lastPercent = -1;

    while (true) {
        int bytesRead = fread(inBuf, 1, BUFFER_SIZE, inFile);
        if (bytesRead <= 0) break;

        if (encrypt) EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
        else         EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);

        fwrite(outBuf, 1, outLen, outFile);
        
        processedBytes += bytesRead;
        if (totalSize > 0) {
            int percent = (processedBytes * 100) / totalSize;
            if (percent != lastPercent && percent <= 100) {
                lastPercent = percent;
                QMetaObject::invokeMethod(bar, [=](){ bar->setValue(percent); }, Qt::QueuedConnection);
            }
        }
    }

    // 5. Finalize (Write Padding)
    if (encrypt) EVP_EncryptFinal_ex(ctx, outBuf, &outLen);
    else         EVP_DecryptFinal_ex(ctx, outBuf, &outLen);
    
    fwrite(outBuf, 1, outLen, outFile);

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(inFile);
    fclose(outFile);

    QMetaObject::invokeMethod(parent, [=](){
        btn->setEnabled(true);
        btn->setText("Start Operation");
        QMessageBox::information(parent, "Success", "AES-256 Operation Complete!");
        bar->setValue(0);
    }, Qt::QueuedConnection);
}

// --- LOGIC: OLD FAST METHOD ---
void processFileFast(std::string inputPath, std::string outputPath, std::string passcode, bool encrypt, 
                     QProgressBar* bar, QPushButton* btn, QWidget* parent) {
    std::vector<int> passDigits;
    for (char c : passcode) {
        if (isdigit(static_cast<unsigned char>(c))) passDigits.push_back(charToInt(c));
    }

    if (passDigits.empty()) {
        QMetaObject::invokeMethod(parent, [=](){
            QMessageBox::warning(parent, "Error", "Passcode must contain at least one digit.");
        }, Qt::QueuedConnection);
        return;
    }

    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile.is_open()) {
        QMetaObject::invokeMethod(parent, [=](){
            QMessageBox::warning(parent, "Error", "Could not open input file.");
        }, Qt::QueuedConnection);
        return;
    }

    inFile.seekg(0, std::ios::end);
    long long totalSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile.is_open()) {
        inFile.close();
        QMetaObject::invokeMethod(parent, [=](){
            QMessageBox::warning(parent, "Error", "Could not open output file.");
        }, Qt::QueuedConnection);
        return;
    }

    std::vector<char> buffer(BUFFER_SIZE);
    const int pssize = static_cast<int>(passDigits.size());
    int passIndex = 0;
    long long processedBytes = 0;
    int lastPercent = -1;

    while (inFile) {
        inFile.read(buffer.data(), BUFFER_SIZE);
        long bytesRead = inFile.gcount();
        if (bytesRead == 0) break;

        for (long i = 0; i < bytesRead; ++i) {
            unsigned char byte = static_cast<unsigned char>(buffer[i]);

            int high = (byte >> 4) & 0x0F;
            int d1 = passDigits[passIndex];
            passIndex = (passIndex + 1) % pssize;
            high = encrypt ? (high + d1) % 16 : (high - d1 + 16) % 16;

            int low = byte & 0x0F;
            int d2 = passDigits[passIndex];
            passIndex = (passIndex + 1) % pssize;
            low = encrypt ? (low + d2) % 16 : (low - d2 + 16) % 16;

            buffer[i] = static_cast<char>((high << 4) | low);
        }

        outFile.write(buffer.data(), bytesRead);
        processedBytes += bytesRead;

        if (totalSize > 0) {
            int percent = static_cast<int>((processedBytes * 100) / totalSize);
            if (percent != lastPercent) {
                lastPercent = percent;
                QMetaObject::invokeMethod(bar, [=](){ bar->setValue(percent); }, Qt::QueuedConnection);
            }
        }
    }

    inFile.close();
    outFile.close();

    QMetaObject::invokeMethod(parent, [=](){
        btn->setEnabled(true);
        btn->setText("Start Operation");
        QMessageBox::information(parent, "Success", "Fast Operation Complete!");
        bar->setValue(0);
    }, Qt::QueuedConnection);
}

// --- UI CLASS ---
class EncryptorWindow : public QWidget {
public:
    QLineEdit *pathEdit;
    QLineEdit *passEdit;
    QProgressBar *progressBar;
    QRadioButton *radioEncrypt;
    QCheckBox *checkAES; // NEW: Checkbox for AES
    QPushButton *btnRun;
    
    EncryptorWindow() {
        setWindowTitle("Pro Encryptor (Debian)");
        QFont font = this->font(); font.setPointSize(10); this->setFont(font);

        QVBoxLayout *mainLayout = new QVBoxLayout(this);
        mainLayout->setContentsMargins(25, 25, 25, 25);
        mainLayout->setSpacing(15);

        // File
        mainLayout->addWidget(new QLabel("File Path:"));
        QHBoxLayout *pathLayout = new QHBoxLayout();
        pathEdit = new QLineEdit(); pathEdit->setPlaceholderText("Select a file...");
        pathLayout->addWidget(pathEdit);
        QPushButton *btnBrowse = new QPushButton("Browse");
        pathLayout->addWidget(btnBrowse);
        mainLayout->addLayout(pathLayout);
        connect(btnBrowse, &QPushButton::clicked, [this]() {
            QString fileName = QFileDialog::getOpenFileName(this, "Select File");
            if(!fileName.isEmpty()) pathEdit->setText(fileName);
        });

        // Passcode
        mainLayout->addWidget(new QLabel("Passcode:"));
        passEdit = new QLineEdit(); passEdit->setEchoMode(QLineEdit::Password);
        mainLayout->addWidget(passEdit);

        // Options
        QGroupBox *gb = new QGroupBox("Settings");
        QVBoxLayout *gbLayout = new QVBoxLayout;
        
        // Mode
        QHBoxLayout *modeLayout = new QHBoxLayout;
        radioEncrypt = new QRadioButton("Encrypt");
        QRadioButton *radioDecrypt = new QRadioButton("Decrypt");
        radioEncrypt->setChecked(true);
        modeLayout->addWidget(radioEncrypt);
        modeLayout->addWidget(radioDecrypt);
        gbLayout->addLayout(modeLayout);

        // Algorithm Choice
        checkAES = new QCheckBox("Use AES-256 (High Security)");
        checkAES->setChecked(true); // Default to Secure
        gbLayout->addWidget(checkAES);

        gb->setLayout(gbLayout);
        mainLayout->addWidget(gb);

        // Progress
        progressBar = new QProgressBar();
        progressBar->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(progressBar);

        // Button
        btnRun = new QPushButton("Start Operation");
        btnRun->setFixedHeight(40);
        btnRun->setStyleSheet("QPushButton { background-color: #28a745; color: white; font-weight: bold; border-radius: 4px; } QPushButton:hover { background-color: #218838; }");
        mainLayout->addWidget(btnRun);

        connect(btnRun, &QPushButton::clicked, [this]() {
            std::string path = pathEdit->text().toStdString();
            std::string pass = passEdit->text().toStdString();
            bool encrypt = radioEncrypt->isChecked();
            bool useAES = checkAES->isChecked();

            if (path.empty() || pass.empty()) {
                QMessageBox::warning(this, "Error", "Fields cannot be empty.");
                return;
            }

            std::string outName;
            if (encrypt) {
                outName = path + (useAES ? ".aes" : ".enc");
            } else {
                const std::string expectedSuffix = useAES ? ".aes" : ".enc";
                if (path.size() <= expectedSuffix.size() || path.rfind(expectedSuffix) != path.size() - expectedSuffix.size()) {
                    QMessageBox::warning(this, "Error", "Selected file extension does not match the chosen mode.");
                    return;
                }

                outName = path.substr(0, path.size() - expectedSuffix.size());
            }

            btnRun->setEnabled(false);
            btnRun->setText("Processing...");

            // Choose Logic based on Checkbox
            if (useAES) {
                std::thread worker(processFileAES, path, outName, pass, encrypt, progressBar, btnRun, this);
                worker.detach();
            } else {
                std::thread worker(processFileFast, path, outName, pass, encrypt, progressBar, btnRun, this);
                worker.detach();
            }
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