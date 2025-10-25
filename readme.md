
# hard-sigs

[![Build and Release](https://github.com/YOUR_USERNAME/hard-sigs/actions/workflows/build-and-release.yml/badge.svg)](https://github.com/YOUR_USERNAME/hard-sigs/actions/workflows/build-and-release.yml)

`hard-sigs` is a cross-platform tool that leverages hardware TPM (Trusted Platform Module), FIDO2 security keys, and smart cards to create cryptographic signatures. It serves as a building block for larger trust systems, providing a simple "proof this hardware is the same hardware as last time" mechanism for cryptographic workflows.

## Quick Start

### Download Pre-built Binaries

The easiest way to get started is to download a pre-built binary from our [GitHub Releases](https://github.com/YOUR_USERNAME/hard-sigs/releases/latest):

- **Windows x64**: `hard-sigs.win.x64.exe`
- **Linux x64**: `hard-sigs.linux.x64`
- **macOS ARM64**: `hard-sigs.mac.arm64`

### Basic Usage

```bash
# Show help
./hard-sigs --help

# List available hardware devices
./hard-sigs --list

# Sign a message with auto-detected device
./hard-sigs "Hello World"

# Sign with specific device type
./hard-sigs --device tpm "Hello World"
./hard-sigs --device fido2 "Hello World"
./hard-sigs --device sc "Hello World"

# Show public keys of all detected devices
./hard-sigs --pubkeys

# Verify a signature
./hard-sigs --verify -s SIGNATURE_HEX -p PUBKEY_HEX "Hello World"
```

## Supported Hardware

- **TPM 2.0**: Hardware Trusted Platform Modules
- **FIDO2**: Security keys (YubiKey, SoloKey, etc.)
- **Smart Cards**: PIV cards and similar PKCS#11 devices

## Building from Source

### Linux
```bash
git clone https://github.com/YOUR_USERNAME/hard-sigs.git
cd hard-sigs
./compile_linux.sh
```

**Dependencies:**
```bash
# Ubuntu/Debian
sudo apt install build-essential pkg-config libtss2-dev libfido2-dev libp11-dev opensc

# Fedora
sudo dnf install gcc pkg-config tpm2-tss-devel libfido2-devel libp11-devel opensc
```

### macOS
```bash
git clone https://github.com/YOUR_USERNAME/hard-sigs.git
cd hard-sigs
./compile_mac.sh
```

**Dependencies:**
```bash
brew install pkg-config tpm2-tss libfido2 libp11 opensc
```

### Windows
```cmd
git clone https://github.com/YOUR_USERNAME/hard-sigs.git
cd hard-sigs
.\compile_win.bat
```

**Requirements:**
- Visual Studio 2019 or later with C++ build tools
- Windows 10/11 SDK

## CI/CD Pipeline

This project uses GitHub Actions to automatically build binaries for all supported platforms on every commit to `master`. The pipeline:

1. **Builds** on Ubuntu (Linux x64), Windows (x64), and macOS (ARM64)
2. **Tests** each binary with `--help` to ensure basic functionality
3. **Creates** a new release with timestamp and commit hash
4. **Publishes** platform-specific binaries as release artifacts

### Workflow Details

- **Trigger**: Push to `master` branch
- **Platforms**: Linux x64, Windows x64, macOS ARM64
- **Artifacts**:
  - `hard-sigs.linux.x64`
  - `hard-sigs.win.x64.exe`
  - `hard-sigs.mac.arm64`
- **Release Format**: `vYYYYMMDD-HHMMSS-{commit}`

## Command Reference

### Signing
```bash
# Auto-detect device and sign
./hard-sigs "message"

# Use specific device
./hard-sigs --device tpm "message"
./hard-sigs --device fido2 "message"
./hard-sigs --device sc "message"
```

### Verification
```bash
./hard-sigs --verify \
  --signature SIGNATURE_HEX \
  --pubkey PUBKEY_HEX \
  "original message"
```

### Device Management
```bash
# List all available devices
./hard-sigs --list

# Show public keys
./hard-sigs --pubkeys
```

## Security Notes

- Signatures are deterministic for verification compatibility
- Private keys never leave the hardware device
- TPM signatures use platform-specific keys
- FIDO2 signatures may require user presence verification
- Smart card operations may require PIN entry

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test on your platform
5. Submit a pull request

The CI pipeline will automatically test your changes on all supported platforms.

## License

This project is licensed GPLv2 only. See LICENSE.txt file for details.

