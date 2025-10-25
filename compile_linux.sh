#!/bin/bash

set -e

echo "Building hard-sigs for Linux..."
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

# Function to check if package is installed (works on most distros)
package_installed() {
    if command_exists dpkg; then
        dpkg -l "$1" >/dev/null 2>&1
    elif command_exists rpm; then
        rpm -q "$1" >/dev/null 2>&1
    elif command_exists pacman; then
        pacman -Q "$1" >/dev/null 2>&1
    elif command_exists apk; then
        apk info -e "$1" >/dev/null 2>&1
    else
        # Fallback: check if header files exist
        [ -f "/usr/include/$1" ] || [ -f "/usr/local/include/$1" ]
    fi
}

# Check for GCC or Clang
echo "Checking for C compiler..."
if command_exists gcc; then
    COMPILER="gcc"
    echo -e "  ${GREEN}✓${NC} GCC found: $(gcc --version | head -n1)"
elif command_exists clang; then
    COMPILER="clang"
    echo -e "  ${GREEN}✓${NC} Clang found: $(clang --version | head -n1)"
else
    echo -e "  ${RED}✗${NC} No C compiler found"
    echo
    echo "ERROR: GCC or Clang is required for compilation."
    echo "Install using your package manager:"
    echo "  Ubuntu/Debian: sudo apt install build-essential"
    echo "  CentOS/RHEL:   sudo yum install gcc"
    echo "  Fedora:        sudo dnf install gcc"
    echo "  Arch Linux:    sudo pacman -S gcc"
    echo "  Alpine:        sudo apk add build-base"
    exit 1
fi

# Check for pkg-config
echo "Checking for pkg-config..."
if command_exists pkg-config; then
    echo -e "  ${GREEN}✓${NC} pkg-config found"
else
    echo -e "  ${RED}✗${NC} pkg-config not found"
    echo
    echo "ERROR: pkg-config is required for dependency detection."
    echo "Install using your package manager:"
    echo "  Ubuntu/Debian: sudo apt install pkg-config"
    echo "  CentOS/RHEL:   sudo yum install pkgconfig"
    echo "  Fedora:        sudo dnf install pkg-config"
    echo "  Arch Linux:    sudo pacman -S pkg-config"
    echo "  Alpine:        sudo apk add pkgconfig"
    exit 1
fi

# Check for required libraries
echo "Checking for required dependencies..."

# Check for TSS2 (TPM library)
TSS2_FOUND=false
if pkg-config --exists tss2-esys 2>/dev/null; then
    TSS2_FOUND=true
    TSS2_CFLAGS=$(pkg-config --cflags tss2-esys)
    TSS2_LIBS=$(pkg-config --libs tss2-esys)
    echo -e "  ${GREEN}✓${NC} TSS2 ESYS library found"
elif [ -f "/usr/include/tss2/tss2_esys.h" ] || [ -f "/usr/local/include/tss2/tss2_esys.h" ]; then
    TSS2_FOUND=true
    TSS2_CFLAGS=""
    TSS2_LIBS="-ltss2-esys -ltss2-sys -ltss2-mu"
    echo -e "  ${GREEN}✓${NC} TSS2 headers found (fallback detection)"
else
    echo -e "  ${YELLOW}⚠${NC} TSS2 library not found"
    echo "    TPM functionality will be limited"
    TSS2_CFLAGS=""
    TSS2_LIBS=""
fi

# Check for libfido2
FIDO2_FOUND=false
if pkg-config --exists libfido2 2>/dev/null; then
    FIDO2_FOUND=true
    FIDO2_CFLAGS=$(pkg-config --cflags libfido2)
    FIDO2_LIBS=$(pkg-config --libs libfido2)
    echo -e "  ${GREEN}✓${NC} libfido2 found"
elif [ -f "/usr/include/fido.h" ] || [ -f "/usr/local/include/fido.h" ] || [ -f "/usr/include/libfido2/fido.h" ]; then
    FIDO2_FOUND=true
    FIDO2_CFLAGS=""
    FIDO2_LIBS="-lfido2"
    echo -e "  ${GREEN}✓${NC} libfido2 headers found (fallback detection)"
else
    echo -e "  ${YELLOW}⚠${NC} libfido2 not found"
    echo "    FIDO2 functionality will be limited"
    FIDO2_CFLAGS=""
    FIDO2_LIBS=""
fi

# Check for smartcard libraries (libp11 and OpenSC)
SMARTCARD_FOUND=false
if pkg-config --exists libp11 2>/dev/null; then
    SMARTCARD_FOUND=true
    SMARTCARD_CFLAGS=$(pkg-config --cflags libp11)
    SMARTCARD_LIBS=$(pkg-config --libs libp11)
    echo -e "  ${GREEN}✓${NC} libp11 found"
elif [ -f "/usr/include/libp11.h" ] || [ -f "/usr/local/include/libp11.h" ]; then
    SMARTCARD_FOUND=true
    SMARTCARD_CFLAGS=""
    SMARTCARD_LIBS="-lp11 -lcrypto -ldl"
    echo -e "  ${GREEN}✓${NC} libp11 headers found (fallback detection)"
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
    if [ "$TSS2_FOUND" = false ]; then
        echo "For TPM support (TSS2):"
        echo "  Ubuntu/Debian: sudo apt install libtss2-dev"
        echo "  CentOS/RHEL:   sudo yum install tpm2-tss-devel"
        echo "  Fedora:        sudo dnf install tpm2-tss-devel"
        echo "  Arch Linux:    sudo pacman -S tpm2-tss"
        echo "  Alpine:        sudo apk add tpm2-tss-dev"
        echo
    fi
    if [ "$FIDO2_FOUND" = false ]; then
        echo "For FIDO2 support:"
        echo "  Ubuntu/Debian: sudo apt install libfido2-dev"
        echo "  CentOS/RHEL:   sudo yum install libfido2-devel"
        echo "  Fedora:        sudo dnf install libfido2-devel"
        echo "  Arch Linux:    sudo pacman -S libfido2"
        echo "  Alpine:        sudo apk add libfido2-dev"
        echo
    fi
    if [ "$SMARTCARD_FOUND" = false ]; then
        echo "For smartcard support:"
        echo "  Ubuntu/Debian: sudo apt install libp11-dev opensc"
        echo "  CentOS/RHEL:   sudo yum install libp11-devel opensc"
        echo "  Fedora:        sudo dnf install libp11-devel opensc"
        echo "  Arch Linux:    sudo pacman -S libp11 opensc"
        echo "  Alpine:        sudo apk add libp11-dev opensc"
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

COMPILE_CMD="$COMPILE_CMD $TSS2_CFLAGS $FIDO2_CFLAGS $SMARTCARD_CFLAGS"
COMPILE_CMD="$COMPILE_CMD $TSS2_LIBS $FIDO2_LIBS $SMARTCARD_LIBS"

# Add common system libraries
COMPILE_CMD="$COMPILE_CMD -lc"

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
    
    echo
    echo "Build complete. You can now run: ./hard-sigs --help"
else
    echo
    echo -e "${RED}ERROR:${NC} Compilation failed."
    echo
    echo "Common issues:"
    echo "  - Missing development headers (install -dev packages)"
    echo "  - Incompatible library versions"
    echo "  - Missing system libraries"
    echo
    echo "Try installing the suggested packages above."
    exit 1
fi