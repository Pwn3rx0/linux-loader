# Makefile for Modular Shellcode Loader

.PHONY: all clean build generate dist test info

# Directories
SRC_DIR = src
PAYLOAD_DIR = $(SRC_DIR)/payload
LOADER_DIR = $(SRC_DIR)/loader
DIST_DIR = dist

# Compiler flags - removed nostdlib and FORTIFY_SOURCE
CC = gcc
CFLAGS = -fPIC -pie -z relro -z now -z noexecstack \
         -O2 -fno-stack-protector -fomit-frame-pointer \
         -Wl,--build-id=none -Wl,--strip-all \
         -s -fvisibility=hidden -ffunction-sections -fdata-sections
LDFLAGS = -Wl,--gc-sections -Wl,--as-needed
INCLUDES = -I$(LOADER_DIR) -I$(PAYLOAD_DIR)

# Source files
SOURCES = $(LOADER_DIR)/main.c \
          $(LOADER_DIR)/decrypt.c \
          $(LOADER_DIR)/executor.c \
          $(LOADER_DIR)/utils.c

# Output binary
OUTPUT = $(DIST_DIR)/shellcode_loader

all: generate build

generate:
	@echo "[*] Generating encrypted payload..."
	@python3 generate.py
	@if [ $$? -ne 0 ]; then \
		echo "[-] Payload generation failed!"; \
		exit 1; \
	fi

build: generate
	@echo "[*] Compiling loader..."
	@mkdir -p $(DIST_DIR)
	@$(CC) $(CFLAGS) $(LDFLAGS) $(INCLUDES) -o $(OUTPUT) $(SOURCES)
	@if [ $$? -ne 0 ]; then \
		echo "[-] Compilation failed!"; \
		exit 1; \
	fi
	@echo "[*] Stripping binary..."
	@strip --strip-all $(OUTPUT) 2>/dev/null || true
	@echo "[+] Build complete: $(OUTPUT)"

clean:
	@echo "[*] Cleaning build artifacts..."
	@rm -rf $(DIST_DIR)
	@rm -f $(PAYLOAD_DIR)/payload.h
	@echo "[+] Clean complete"

distclean: clean
	@rm -f shellcode.bin

dist: clean all
	@echo "[*] Creating distribution..."
	@echo "[+] Distribution ready in $(DIST_DIR)"

test: build
	@echo "[*] Testing binary..."
	@file $(OUTPUT)
	@echo ""
	@echo "[*] Security check:"
	@checksec --file=$(OUTPUT) 2>/dev/null || echo "[!] Install checksec for detailed security analysis"
	@echo ""
	@echo "[*] Running loader with test shellcode..."
	@if [ -f "shellcode.bin" ]; then \
		echo "[+] Found shellcode.bin"; \
		$(OUTPUT) || echo "[+] Shellcode executed (exit code: $$?)"; \
	else \
		echo "[-] No shellcode.bin found"; \
		echo "[*] Creating test shellcode (exit 42)..."; \
		echo -n -e "\x48\x31\xff\x48\x83\xc7\x2a\x48\x31\xc0\xb0\x3c\x0f\x05" > shellcode.bin; \
		make generate && $(OUTPUT) || echo "[+] Test shellcode executed (exit code: $$?)"; \
	fi

info:
	@echo "[*] Project Information:"
	@echo "  Source dir: $(SRC_DIR)"
	@echo "  Loader dir: $(LOADER_DIR)"
	@echo "  Payload dir: $(PAYLOAD_DIR)"
	@echo "  Dist dir: $(DIST_DIR)"
	@echo ""
	@if [ -f "$(OUTPUT)" ]; then \
		echo "[*] Binary Information:"; \
		file $(OUTPUT); \
		echo ""; \
		echo "[*] Checking for symbols:"; \
		nm -g $(OUTPUT) 2>/dev/null | wc -l | xargs echo "  Symbols count:"; \
		readelf -s $(OUTPUT) 2>/dev/null | grep "FUNC" | wc -l | xargs echo "  Function symbols:"; \
	else \
		echo "[-] Binary not built. Run 'make all' first."; \
	fi

help:
	@echo "Available targets:"
	@echo "  make all     - Generate payload and build loader"
	@echo "  make generate - Generate encrypted payload only"
	@echo "  make build   - Build loader (requires payload)"
	@echo "  make clean   - Remove build artifacts"
	@echo "  make distclean - Remove everything including shellcode"
	@echo "  make test    - Build and test with example shellcode"
	@echo "  make info    - Show project information"
	@echo "  make help    - Show this help"

# Debug target to see what files are being compiled
debug:
	@echo "Compiler: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"
	@echo "INCLUDES: $(INCLUDES)"
	@echo "SOURCES: $(SOURCES)"
	@echo "OUTPUT: $(OUTPUT)"