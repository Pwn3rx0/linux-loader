# Modular Shellcode Loader for Linux

A lightweight, modular shellcode loader for Linux with triple XOR encryption and modern evasion techniques.


## VirusTotal Results
![Screenshot_2026-01-30_19-20-11](https://github.com/user-attachments/assets/d1c02030-2b40-4426-a9ad-bf9fe148c4cd)

**0/70 detections** - Fully undetected by all major AV engines


## 🚀 Quick Start

### 1. Clone & Setup
```bash
git clone https://github.com/yourusername/shellcode-loader.git
cd shellcode-loader
# replace shellcode.bin with your own
make all
./dist/shellcode_loader
```
## 🛡️ Features

- **Triple XOR Encryption** - Each byte encrypted with 3 unique keys
- **String Splitting** - Strings assembled at runtime to evade detection
- **Binary Hardening** - Full PIE, RELRO, stripped symbols, no execstack
- **Modular Design** - Clean separation of decryption, execution, and utilities
- **No Anti-VM/Debug** - Focused on core functionality without anti-analysis


## ⚠️ Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**

