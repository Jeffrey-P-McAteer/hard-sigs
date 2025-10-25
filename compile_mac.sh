#!/bin/bash

set -e

echo "Building hard-sigs for macOS..."
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if Homebrew package is installed
brew_package_installed() {
    if command_exists brew; then
        brew list "$1" >/dev/null 2>&1
    else
        return 1
    fi
}

# Check for Xcode Command Line Tools
echo "Checking for development tools..."
if command_exists clang && command_exists make; then
    echo -e "  ${GREEN}✓${NC} Xcode Command Line Tools found"
    COMPILER="clang"
    echo -e "  ${GREEN}✓${NC} Clang found: $(clang --version | head -n1)"
elif xcode-select -p >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Xcode found"
    COMPILER="clang"
else
    echo -e "  ${RED}✗${NC} Xcode Command Line Tools not found"
    echo
    echo "ERROR: Xcode Command Line Tools are required for compilation."
    echo "Install using: xcode-select --install"
    echo "Or install Xcode from the App Store."
    exit 1
fi

# Check for Homebrew
echo "Checking for Homebrew..."
if command_exists brew; then
    echo -e "  ${GREEN}✓${NC} Homebrew found: $(brew --version | head -n1)"
else
    echo -e "  ${YELLOW}⚠${NC} Homebrew not found"
    echo "  Homebrew is recommended for installing dependencies."
    echo "  Install from: https://brew.sh"
    echo
fi

# Check for pkg-config
echo "Checking for pkg-config..."
if command_exists pkg-config; then
    echo -e "  ${GREEN}✓${NC} pkg-config found"
elif command_exists brew && brew_package_installed pkg-config; then
    echo -e "  ${GREEN}✓${NC} pkg-config found via Homebrew"
    export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig:/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH"
else
    echo -e "  ${YELLOW}⚠${NC} pkg-config not found"
    if command_exists brew; then
        echo "  You can install it with: brew install pkg-config"
    fi
    echo "  Continuing with manual dependency detection..."
fi

# Check for required libraries
echo "Checking for required dependencies..."

# TPM support on macOS is limited, but we'll check anyway
TSS2_FOUND=false
if command_exists pkg-config && pkg-config --exists tss2-esys 2>/dev/null; then
    TSS2_FOUND=true
    TSS2_CFLAGS=$(pkg-config --cflags tss2-esys)
    TSS2_LIBS=$(pkg-config --libs tss2-esys)
    echo -e "  ${GREEN}✓${NC} TSS2 ESYS library found"
elif [ -f "/opt/homebrew/include/tss2/tss2_esys.h" ] || [ -f "/usr/local/include/tss2/tss2_esys.h" ]; then
    TSS2_FOUND=true
    TSS2_CFLAGS="-I/opt/homebrew/include -I/usr/local/include"
    TSS2_LIBS="-L/opt/homebrew/lib -L/usr/local/lib -ltss2-esys -ltss2-sys -ltss2-mu"
    echo -e "  ${GREEN}✓${NC} TSS2 headers found"
else
    echo -e "  ${YELLOW}⚠${NC} TSS2 library not found"
    echo "    TPM functionality will be limited on macOS"
    TSS2_CFLAGS=""
    TSS2_LIBS=""
fi

# Check for libfido2
FIDO2_FOUND=false
if command_exists pkg-config && pkg-config --exists libfido2 2>/dev/null; then
    FIDO2_FOUND=true
    FIDO2_CFLAGS=$(pkg-config --cflags libfido2)
    FIDO2_LIBS=$(pkg-config --libs libfido2)
    echo -e "  ${GREEN}✓${NC} libfido2 found via pkg-config"
elif [ -f "/opt/homebrew/include/fido.h" ] || [ -f "/usr/local/include/fido.h" ] || [ -f "/opt/homebrew/include/libfido2/fido.h" ] || [ -f "/usr/local/include/libfido2/fido.h" ]; then
    FIDO2_FOUND=true
    FIDO2_CFLAGS="-I/opt/homebrew/include -I/usr/local/include"
    FIDO2_LIBS="-L/opt/homebrew/lib -L/usr/local/lib -lfido2"
    echo -e "  ${GREEN}✓${NC} libfido2 headers found"
else
    echo -e "  ${YELLOW}⚠${NC} libfido2 not found"
    echo "    FIDO2 functionality will be limited"
    FIDO2_CFLAGS=""
    FIDO2_LIBS=""
fi

# Check for smartcard libraries (libp11)
SMARTCARD_FOUND=false
if command_exists pkg-config && pkg-config --exists libp11 2>/dev/null; then
    SMARTCARD_FOUND=true
    SMARTCARD_CFLAGS=$(pkg-config --cflags libp11)
    SMARTCARD_LIBS=$(pkg-config --libs libp11)
    echo -e "  ${GREEN}✓${NC} libp11 found via pkg-config"
elif [ -f "/opt/homebrew/include/libp11.h" ] || [ -f "/usr/local/include/libp11.h" ]; then
    SMARTCARD_FOUND=true
    SMARTCARD_CFLAGS="-I/opt/homebrew/include -I/usr/local/include"
    SMARTCARD_LIBS="-L/opt/homebrew/lib -L/usr/local/lib -lp11 -lcrypto"
    echo -e "  ${GREEN}✓${NC} libp11 headers found"
else
    echo -e "  ${YELLOW}⚠${NC} libp11 not found"
    echo "    Smartcard functionality will be limited"
    SMARTCARD_CFLAGS=""
    SMARTCARD_LIBS=""
fi

# Print installation suggestions if libraries are missing
if [ "$TSS2_FOUND" = false ] || [ "$FIDO2_FOUND" = false ] || [ "$SMARTCARD_FOUND" = false ]; then
    echo
    echo "Optional dependencies missing. To install:"
    echo
    if command_exists brew; then
        if [ "$TSS2_FOUND" = false ]; then
            echo "For TPM support (TSS2):"
            echo "  brew install tpm2-tss"
            echo "  Note: TPM support on macOS is limited"
            echo
        fi
        if [ "$FIDO2_FOUND" = false ]; then
            echo "For FIDO2 support:"
            echo "  brew install libfido2"
            echo
        fi
        if [ "$SMARTCARD_FOUND" = false ]; then
            echo "For smartcard support:"
            echo "  brew install libp11 opensc"
            echo
        fi
    else
        echo "Install Homebrew first: https://brew.sh"
        echo "Then install dependencies as shown above."
        echo
    fi
    echo "Continuing with limited functionality..."
    echo
fi

# Check if source file exists
if [ ! -f "hard-sigs.c" ]; then
    echo -e "${RED}ERROR:${NC} Source file 'hard-sigs.c' not found in current directory."
    exit 1
fi

echo "Compiling hard-sigs.c..."

# Build compiler command
COMPILE_CMD="$COMPILER -std=c99 -Wall -Wextra -O2 -o hard-sigs hard-sigs.c"

# Add defines based on available libraries
if [ "$SMARTCARD_FOUND" = true ]; then
    COMPILE_CMD="$COMPILE_CMD -DHAVE_SMARTCARD"
fi

# Add framework for macOS Security framework
COMPILE_CMD="$COMPILE_CMD -framework Security -framework CoreFoundation"

# Add library flags
COMPILE_CMD="$COMPILE_CMD $TSS2_CFLAGS $FIDO2_CFLAGS $SMARTCARD_CFLAGS"
COMPILE_CMD="$COMPILE_CMD $TSS2_LIBS $FIDO2_LIBS $SMARTCARD_LIBS"

echo "Executing: $COMPILE_CMD"
echo

# Compile
if eval "$COMPILE_CMD"; then
    echo
    echo -e "${GREEN}✓${NC} Compilation successful!"
    echo "Created: hard-sigs"
    
    # Make executable
    chmod +x hard-sigs
    
    # Test the executable
    echo
    echo "Testing executable..."
    if ./hard-sigs --help >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Executable test passed"
    else
        echo -e "${YELLOW}⚠${NC} Executable test failed. Program may have runtime dependencies."
        echo "You may need to install runtime libraries:"
        if [ "$TSS2_FOUND" = true ]; then
            echo "  - TPM2 TSS runtime libraries"
        fi
        if [ "$FIDO2_FOUND" = true ]; then
            echo "  - libfido2 runtime libraries"
        fi
        if [ "$SMARTCARD_FOUND" = true ]; then
            echo "  - libp11 and OpenSC runtime libraries"
        fi
    fi
    
    # Check for code signing (optional but recommended for distribution)
    echo
    echo "Checking code signing..."
    if command_exists codesign; then
        if codesign -v hard-sigs 2>/dev/null; then
            echo -e "${GREEN}✓${NC} Executable is code signed"
        else
            echo -e "${YELLOW}⚠${NC} Executable is not code signed"
            echo "  For distribution, consider signing with: codesign -s 'Developer ID' hard-sigs"
        fi
    fi
    
    echo
    echo "Build complete. You can now run: ./hard-sigs --help"
else
    echo
    echo -e "${RED}ERROR:${NC} Compilation failed."
    echo
    echo "Common issues:"
    echo "  - Missing Xcode Command Line Tools"
    echo "  - Missing development headers (install via Homebrew)"
    echo "  - Incompatible library versions"
    echo "  - Architecture mismatches (Intel vs Apple Silicon)"
    echo
    echo "Try installing the suggested packages above."
    echo "For Apple Silicon Macs, ensure you're using the correct Homebrew path."
    exit 1
fi