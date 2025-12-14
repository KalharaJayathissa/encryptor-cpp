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
#include <QGroupBox>

#include <fstream>
#include <vector>
#include <string>
#include <thread> // Standard C++ Threading
#include <atomic> // For thread-safe flags

// --- Logic ---
const size_t BUFFER_SIZE = 65536;

int charToInt(char c) { return c - '0'; }

// We pass pointers to UI elements so the thread knows where to send updates
void processFileThreaded(std::string inputPath, std::string outputPath, std::string passcode, bool encrypt, 
                         QProgressBar* bar, QPushButton* btn, QWidget* parent) {
    
    std::vector<int> passDigits;
    for (char c : passcode) {
        if (isdigit(c)) passDigits.push_back(charToInt(c));
    }

    std::ifstream inFile(inputPath, std::ios::binary);
    
    // Calculate Size
    inFile.seekg(0, std::ios::end);
    long long totalSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    std::ofstream outFile(outputPath, std::ios::binary);
    std::vector<char> buffer(BUFFER_SIZE);
    
    int pssize = passDigits.size();
    int passIndex = 0; 
    long long processedBytes = 0;
    int lastPercent = -1;

    // --- MAIN LOOP (Running in Background) ---
    while (inFile) {
        inFile.read(buffer.data(), BUFFER_SIZE);
        long bytesRead = inFile.gcount();
        if (bytesRead == 0) break; 

        // Encryption/Decryption Math
        for (long i = 0; i < bytesRead; ++i) {
            unsigned char byte = static_cast<unsigned char>(buffer[i]);
            
            // High Nibble
            int high = (byte >> 4) & 0x0F;
            int d1 = passDigits[passIndex];
            passIndex = (passIndex + 1) % pssize;
            high = encrypt ? (high + d1) % 16 : (high - d1 + 16) % 16;

            // Low Nibble
            int low = byte & 0x0F;
            int d2 = passDigits[passIndex];
            passIndex = (passIndex + 1) % pssize;
            low = encrypt ? (low + d2) % 16 : (low - d2 + 16) % 16;

            buffer[i] = static_cast<char>((high << 4) | low);
        }

        outFile.write(buffer.data(), bytesRead);
        processedBytes += bytesRead;

        // --- SAFE UI UPDATE ---
        if (totalSize > 0) {
            int percent = (processedBytes * 100) / totalSize;
            
            // Only update if percentage changed (optimizes performance)
            if (percent != lastPercent) {
                lastPercent = percent;
                
                // Magic Line: Schedule this update to run on the MAIN thread
                QMetaObject::invokeMethod(bar, [=](){ 
                    bar->setValue(percent); 
                }, Qt::QueuedConnection);
            }
        }
    }

    // --- CLEANUP ---
    inFile.close();
    outFile.close();

    // Re-enable the button and show success message on Main Thread
    QMetaObject::invokeMethod(parent, [=](){
        btn->setEnabled(true);
        btn->setText("Start");
        QMessageBox::information(parent, "Success", "Operation Complete!");
        bar->setValue(0);
    }, Qt::QueuedConnection);
}

// --- The UI Class ---
class EncryptorWindow : public QWidget {
public:
    QLineEdit *pathEdit;
    QLineEdit *passEdit;
    QProgressBar *progressBar;
    QRadioButton *radioEncrypt;
    QPushButton *btnRun;
    
    EncryptorWindow() {
        setWindowTitle("Threaded Fast Encryptor");
        setFixedSize(400, 300);
        QVBoxLayout *layout = new QVBoxLayout(this);

        // UI Setup (Same as before)
        layout->addWidget(new QLabel("File Path:"));
        pathEdit = new QLineEdit();
        layout->addWidget(pathEdit);
        QPushButton *btnBrowse = new QPushButton("Browse...");
        layout->addWidget(btnBrowse);
        
        connect(btnBrowse, &QPushButton::clicked, [this]() {
            QString fileName = QFileDialog::getOpenFileName(this, "Select File");
            if(!fileName.isEmpty()) pathEdit->setText(fileName);
        });

        layout->addWidget(new QLabel("Passcode:"));
        passEdit = new QLineEdit();
        passEdit->setEchoMode(QLineEdit::Password);
        layout->addWidget(passEdit);

        QGroupBox *gb = new QGroupBox("Mode");
        QVBoxLayout *gbLayout = new QVBoxLayout;
        radioEncrypt = new QRadioButton("Encrypt");
        QRadioButton *radioDecrypt = new QRadioButton("Decrypt");
        radioEncrypt->setChecked(true);
        gbLayout->addWidget(radioEncrypt);
        gbLayout->addWidget(radioDecrypt);
        gb->setLayout(gbLayout);
        layout->addWidget(gb);

        progressBar = new QProgressBar();
        progressBar->setValue(0);
        layout->addWidget(progressBar);

        btnRun = new QPushButton("Start");
        layout->addWidget(btnRun);

        // Button Click Logic
        connect(btnRun, &QPushButton::clicked, [this]() {
            std::string path = pathEdit->text().toStdString();
            std::string pass = passEdit->text().toStdString();
            bool encrypt = radioEncrypt->isChecked();

            if (path.empty() || pass.empty()) {
                QMessageBox::warning(this, "Error", "Fill all fields");
                return;
            }

            std::string outName = encrypt ? path + ".enc" : path + ".dec";

            // Disable button so user doesn't click twice
            btnRun->setEnabled(false);
            btnRun->setText("Running...");

            // --- LAUNCH THREAD ---
            // We create a new C++ thread that runs 'processFileThreaded'
            std::thread worker(processFileThreaded, path, outName, pass, encrypt, progressBar, btnRun, this);
            
            // Detach allows the thread to run independently
            worker.detach(); 
        });
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    EncryptorWindow window;
    window.show();
    return app.exec();
}