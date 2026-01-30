#!/usr/bin/env python3
import os
import sys
import random
import struct
from pathlib import Path

def generate_random_key():
    """Generate random XOR key avoiding null bytes"""
    key = random.randint(0x01, 0xFF)
    while key == 0:
        key = random.randint(0x01, 0xFF)
    return key

def triple_xor_encrypt(shellcode):
    """Encrypt shellcode with three different XOR keys in different order"""
    key1 = generate_random_key()
    key2 = generate_random_key()
    key3 = generate_random_key()
    
    print(f"[+] Generated keys: {key1:#04x}, {key2:#04x}, {key3:#04x}")
    
    # First XOR with key3
    encrypted = bytearray()
    for byte in shellcode:
        encrypted.append(byte ^ key3)
    
    # Second XOR with key2
    for i in range(len(encrypted)):
        encrypted[i] ^= key2
    
    # Third XOR with key1
    for i in range(len(encrypted)):
        encrypted[i] ^= key1
    
    return bytes(encrypted), (key1, key2, key3)

def split_strings(data, chunk_size=2):
    """Split strings into chunks to avoid detection"""
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        chunks.append(chunk)
    return chunks

def generate_header(payload, keys):
    """Generate C header file with obfuscated payload"""
    header_content = []
    header_content.append("#ifndef PAYLOAD_H")
    header_content.append("#define PAYLOAD_H\n")
    
    # Add keys as separate constants
    header_content.append(f"#define KEY1 {keys[0]}")
    header_content.append(f"#define KEY2 {keys[1]}")
    header_content.append(f"#define KEY3 {keys[2]}\n")
    
    # Split payload into chunks
    chunks = split_strings(payload, 16)
    header_content.append(f"static const unsigned char PAYLOAD[] = {{")
    
    chunk_strings = []
    for i, chunk in enumerate(chunks):
        hex_values = ', '.join([f"0x{b:02x}" for b in chunk])
        chunk_strings.append(f"    {hex_values}")
    
    header_content.append(',\n'.join(chunk_strings))
    header_content.append("};\n")
    
    header_content.append(f"#define PAYLOAD_SIZE {len(payload)}")
    header_content.append("#endif // PAYLOAD_H")
    
    return '\n'.join(header_content)

def main():
    # Paths
    current_dir = Path(__file__).parent
    shellcode_path = current_dir / "shellcode.bin"
    payload_dir = current_dir / "src" / "payload"
    header_path = payload_dir / "payload.h"
    
    # Create payload directory if it doesn't exist
    payload_dir.mkdir(parents=True, exist_ok=True)
    
    # Read shellcode
    if not shellcode_path.exists():
        print(f"[-] Error: {shellcode_path} not found!")
        print(f"[*] Creating example shellcode (exit 42)")
        # Example shellcode: exit(42)
        example_shellcode = bytes([
            0x48, 0x31, 0xff,       # xor rdi, rdi
            0x48, 0x83, 0xc7, 0x2a, # add rdi, 42
            0x48, 0x31, 0xc0,       # xor rax, rax
            0xb0, 0x3c,             # mov al, 60 (exit syscall)
            0x0f, 0x05              # syscall
        ])
        with open(shellcode_path, "wb") as f:
            f.write(example_shellcode)
        shellcode = example_shellcode
    else:
        with open(shellcode_path, "rb") as f:
            shellcode = f.read()
    
    print(f"[+] Read {len(shellcode)} bytes from shellcode.bin")
    
    # Encrypt shellcode
    encrypted_payload, keys = triple_xor_encrypt(shellcode)
    print(f"[+] Encrypted payload size: {len(encrypted_payload)} bytes")
    
    # Generate header
    header_content = generate_header(encrypted_payload, keys)
    
    # Write header
    with open(header_path, "w") as f:
        f.write(header_content)
    
    print(f"[+] Generated {header_path}")
    return 0

if __name__ == "__main__":
    sys.exit(main())