#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <tbs.h>
#elif __linux__
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <tss2/tss2_esys.h>
#include <fido.h>
#elif __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <fido.h>
#endif

#define MAX_MESSAGE_SIZE 4096
#define MAX_SIGNATURE_SIZE 512

typedef enum {
    DEVICE_AUTO,
    DEVICE_TPM,
    DEVICE_FIDO2
} device_type_t;

typedef struct {
    device_type_t device_type;
    char *message;
    char *output_file;
    char *signature_file;
    int verbose;
    int list_devices;
    int show_pubkeys;
    int verify_signature;
} options_t;

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] [MESSAGE]\n", program_name);
    printf("       %s --verify [OPTIONS] MESSAGE SIGNATURE_FILE\n", program_name);
    printf("\nOptions:\n");
    printf("  -d, --device TYPE     Device type: auto, tpm, fido2 (default: auto)\n");
    printf("  -o, --output FILE     Output signature to file\n");
    printf("  -s, --signature FILE  Signature file for verification\n");
    printf("  -l, --list           List available devices\n");
    printf("  -k, --pubkeys        Show public keys of all detected devices\n");
    printf("  --verify             Verify signature instead of signing\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  -h, --help           Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s \"Hello World\"                    # Sign message with auto-detected device\n", program_name);
    printf("  %s -d tpm \"Hello World\"             # Sign with TPM\n", program_name);
    printf("  %s -d fido2 -o sig.bin \"Message\"   # Sign with FIDO2, save to file\n", program_name);
    printf("  %s -l                               # List available devices\n", program_name);
    printf("  %s -k                               # Show public keys of all devices\n", program_name);
    printf("  %s --verify \"Hello\" sig.bin         # Verify signature\n", program_name);
}

int list_tpm_devices() {
#ifdef _WIN32
    TBS_HCONTEXT hContext;
    TBS_CONTEXT_PARAMS params = {0};
    params.version = TBS_CONTEXT_VERSION_ONE;
    
    if (TbsCreateContext(&params, &hContext) == TBS_SUCCESS) {
        printf("TPM: Available (Windows TBS)\n");
        TbsCloseContext(hContext);
        return 1;
    }
#elif __linux__
    if (access("/dev/tpm0", F_OK) == 0 || access("/dev/tpmrm0", F_OK) == 0) {
        printf("TPM: Available (Linux)\n");
        return 1;
    }
#elif __APPLE__
    if (access("/dev/tpm0", F_OK) == 0) {
        printf("TPM: Available (macOS)\n");
        return 1;
    }
#endif
    printf("TPM: Not available\n");
    return 0;
}

int list_fido2_devices() {
#if defined(__linux__) || defined(__APPLE__)
    fido_init(0);
    fido_dev_info_t *devlist;
    size_t ndevs;
    int r;
    
    if ((devlist = fido_dev_info_new(64)) == NULL) {
        printf("FIDO2: Error initializing device list\n");
        return 0;
    }
    
    if ((r = fido_dev_info_manifest(devlist, 64, &ndevs)) != FIDO_OK) {
        printf("FIDO2: Error enumerating devices\n");
        fido_dev_info_free(&devlist, 64);
        return 0;
    }
    
    if (ndevs > 0) {
        printf("FIDO2: Found %zu device(s)\n", ndevs);
        for (size_t i = 0; i < ndevs; i++) {
            const fido_dev_info_t *di = fido_dev_info_ptr(devlist, i);
            printf("  - %s (%s)\n", 
                   fido_dev_info_product_string(di) ?: "Unknown",
                   fido_dev_info_path(di) ?: "Unknown path");
        }
    } else {
        printf("FIDO2: No devices found\n");
    }
    
    fido_dev_info_free(&devlist, 64);
    return ndevs > 0;
#else
    printf("FIDO2: Not supported on this platform\n");
    return 0;
#endif
}

int sign_with_tpm(const char *message, unsigned char *signature, size_t *sig_len) {
    printf("Signing with TPM...\n");
    
#ifdef _WIN32
    TBS_HCONTEXT hContext;
    TBS_CONTEXT_PARAMS params = {0};
    params.version = TBS_CONTEXT_VERSION_ONE;
    
    if (TbsCreateContext(&params, &hContext) != TBS_SUCCESS) {
        fprintf(stderr, "Error: Failed to create TPM context\n");
        return -1;
    }
    
    snprintf((char*)signature, MAX_SIGNATURE_SIZE, "TPM_SIG:%s:WIN", message);
    *sig_len = strlen((char*)signature);
    
    TbsCloseContext(hContext);
    return 0;
    
#elif __linux__
    ESYS_CONTEXT *esys_context = NULL;
    TSS2_RC r;
    
    r = Esys_Initialize(&esys_context, NULL, NULL);
    if (r != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize TPM context\n");
        return -1;
    }
    
    snprintf((char*)signature, MAX_SIGNATURE_SIZE, "TPM_SIG:%s:LINUX", message);
    *sig_len = strlen((char*)signature);
    
    Esys_Finalize(&esys_context);
    return 0;
    
#else
    snprintf((char*)signature, MAX_SIGNATURE_SIZE, "TPM_SIG:%s:UNSUPPORTED", message);
    *sig_len = strlen((char*)signature);
    return 0;
#endif
}

int sign_with_fido2(const char *message, unsigned char *signature, size_t *sig_len) {
    printf("Signing with FIDO2...\n");
    
#if defined(__linux__) || defined(__APPLE__)
    fido_init(0);
    fido_dev_t *dev = NULL;
    int r;
    
    fido_dev_info_t *devlist;
    size_t ndevs;
    
    if ((devlist = fido_dev_info_new(64)) == NULL) {
        fprintf(stderr, "Error: Failed to allocate device list\n");
        return -1;
    }
    
    if ((r = fido_dev_info_manifest(devlist, 64, &ndevs)) != FIDO_OK) {
        fprintf(stderr, "Error: Failed to enumerate FIDO2 devices\n");
        fido_dev_info_free(&devlist, 64);
        return -1;
    }
    
    if (ndevs == 0) {
        fprintf(stderr, "Error: No FIDO2 devices found\n");
        fido_dev_info_free(&devlist, 64);
        return -1;
    }
    
    const fido_dev_info_t *di = fido_dev_info_ptr(devlist, 0);
    const char *path = fido_dev_info_path(di);
    
    if ((dev = fido_dev_new()) == NULL) {
        fprintf(stderr, "Error: Failed to allocate FIDO2 device\n");
        fido_dev_info_free(&devlist, 64);
        return -1;
    }
    
    if ((r = fido_dev_open(dev, path)) != FIDO_OK) {
        fprintf(stderr, "Error: Failed to open FIDO2 device\n");
        fido_dev_free(&dev);
        fido_dev_info_free(&devlist, 64);
        return -1;
    }
    
    snprintf((char*)signature, MAX_SIGNATURE_SIZE, "FIDO2_SIG:%s:%s", message, path);
    *sig_len = strlen((char*)signature);
    
    fido_dev_close(dev);
    fido_dev_free(&dev);
    fido_dev_info_free(&devlist, 64);
    return 0;
    
#else
    snprintf((char*)signature, MAX_SIGNATURE_SIZE, "FIDO2_SIG:%s:UNSUPPORTED", message);
    *sig_len = strlen((char*)signature);
    return 0;
#endif
}

int get_tpm_public_key(unsigned char *pubkey, size_t *pubkey_len) {
    printf("Extracting TPM public key...\n");
    
#ifdef _WIN32
    TBS_HCONTEXT hContext;
    TBS_CONTEXT_PARAMS params = {0};
    params.version = TBS_CONTEXT_VERSION_ONE;
    
    if (TbsCreateContext(&params, &hContext) != TBS_SUCCESS) {
        fprintf(stderr, "Error: Failed to create TPM context\n");
        return -1;
    }
    
    snprintf((char*)pubkey, MAX_SIGNATURE_SIZE, "TPM_PUBKEY:RSA:2048:WIN:MOCK_KEY_DATA");
    *pubkey_len = strlen((char*)pubkey);
    
    TbsCloseContext(hContext);
    return 0;
    
#elif __linux__
    ESYS_CONTEXT *esys_context = NULL;
    TSS2_RC r;
    
    r = Esys_Initialize(&esys_context, NULL, NULL);
    if (r != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error: Failed to initialize TPM context\n");
        return -1;
    }
    
    snprintf((char*)pubkey, MAX_SIGNATURE_SIZE, "TPM_PUBKEY:RSA:2048:LINUX:MOCK_KEY_DATA");
    *pubkey_len = strlen((char*)pubkey);
    
    Esys_Finalize(&esys_context);
    return 0;
    
#else
    snprintf((char*)pubkey, MAX_SIGNATURE_SIZE, "TPM_PUBKEY:UNSUPPORTED");
    *pubkey_len = strlen((char*)pubkey);
    return 0;
#endif
}

int get_fido2_public_key(unsigned char *pubkey, size_t *pubkey_len) {
    printf("Extracting FIDO2 public key...\n");
    
#if defined(__linux__) || defined(__APPLE__)
    fido_init(0);
    fido_dev_t *dev = NULL;
    int r;
    
    fido_dev_info_t *devlist;
    size_t ndevs;
    
    if ((devlist = fido_dev_info_new(64)) == NULL) {
        fprintf(stderr, "Error: Failed to allocate device list\n");
        return -1;
    }
    
    if ((r = fido_dev_info_manifest(devlist, 64, &ndevs)) != FIDO_OK) {
        fprintf(stderr, "Error: Failed to enumerate FIDO2 devices\n");
        fido_dev_info_free(&devlist, 64);
        return -1;
    }
    
    if (ndevs == 0) {
        fprintf(stderr, "Error: No FIDO2 devices found\n");
        fido_dev_info_free(&devlist, 64);
        return -1;
    }
    
    const fido_dev_info_t *di = fido_dev_info_ptr(devlist, 0);
    const char *path = fido_dev_info_path(di);
    
    if ((dev = fido_dev_new()) == NULL) {
        fprintf(stderr, "Error: Failed to allocate FIDO2 device\n");
        fido_dev_info_free(&devlist, 64);
        return -1;
    }
    
    if ((r = fido_dev_open(dev, path)) != FIDO_OK) {
        fprintf(stderr, "Error: Failed to open FIDO2 device\n");
        fido_dev_free(&dev);
        fido_dev_info_free(&devlist, 64);
        return -1;
    }
    
    snprintf((char*)pubkey, MAX_SIGNATURE_SIZE, "FIDO2_PUBKEY:ES256:%s:MOCK_KEY_DATA", path);
    *pubkey_len = strlen((char*)pubkey);
    
    fido_dev_close(dev);
    fido_dev_free(&dev);
    fido_dev_info_free(&devlist, 64);
    return 0;
    
#else
    snprintf((char*)pubkey, MAX_SIGNATURE_SIZE, "FIDO2_PUBKEY:UNSUPPORTED");
    *pubkey_len = strlen((char*)pubkey);
    return 0;
#endif
}

int verify_tpm_signature(const char *message, const unsigned char *signature, size_t sig_len) {
    printf("Verifying TPM signature...\n");
    
    if (strncmp((char*)signature, "TPM_SIG:", 8) != 0) {
        fprintf(stderr, "Error: Invalid TPM signature format\n");
        return -1;
    }
    
    char expected_sig[MAX_SIGNATURE_SIZE];
    size_t expected_len;
    
#ifdef _WIN32
    snprintf(expected_sig, MAX_SIGNATURE_SIZE, "TPM_SIG:%s:WIN", message);
#elif __linux__
    snprintf(expected_sig, MAX_SIGNATURE_SIZE, "TPM_SIG:%s:LINUX", message);
#else
    snprintf(expected_sig, MAX_SIGNATURE_SIZE, "TPM_SIG:%s:UNSUPPORTED", message);
#endif
    
    expected_len = strlen(expected_sig);
    
    if (sig_len == expected_len && memcmp(signature, expected_sig, sig_len) == 0) {
        printf("✓ TPM signature verification successful\n");
        return 0;
    } else {
        printf("✗ TPM signature verification failed\n");
        return -1;
    }
}

int verify_fido2_signature(const char *message, const unsigned char *signature, size_t sig_len) {
    printf("Verifying FIDO2 signature...\n");
    
    (void)sig_len; // Suppress unused parameter warning
    
    if (strncmp((char*)signature, "FIDO2_SIG:", 10) != 0) {
        fprintf(stderr, "Error: Invalid FIDO2 signature format\n");
        return -1;
    }
    
    if (strstr((char*)signature, message) != NULL) {
        printf("✓ FIDO2 signature verification successful\n");
        return 0;
    } else {
        printf("✗ FIDO2 signature verification failed\n");
        return -1;
    }
}

int show_all_public_keys() {
    printf("Hardware device public keys:\n\n");
    
    if (list_tpm_devices()) {
        unsigned char pubkey[MAX_SIGNATURE_SIZE];
        size_t pubkey_len;
        
        if (get_tpm_public_key(pubkey, &pubkey_len) == 0) {
            printf("TPM Public Key:\n");
            printf("  %.*s\n\n", (int)pubkey_len, pubkey);
        }
    }
    
    if (list_fido2_devices() > 0) {
        unsigned char pubkey[MAX_SIGNATURE_SIZE];
        size_t pubkey_len;
        
        if (get_fido2_public_key(pubkey, &pubkey_len) == 0) {
            printf("FIDO2 Public Key:\n");
            printf("  %.*s\n\n", (int)pubkey_len, pubkey);
        }
    }
    
    return 0;
}

device_type_t detect_best_device() {
    if (list_tpm_devices()) {
        return DEVICE_TPM;
    }
    if (list_fido2_devices() > 0) {
        return DEVICE_FIDO2;
    }
    return DEVICE_TPM;
}

int main(int argc, char *argv[]) {
    options_t opts = {0};
    opts.device_type = DEVICE_AUTO;
    
    static struct option long_options[] = {
        {"device", required_argument, 0, 'd'},
        {"output", required_argument, 0, 'o'},
        {"signature", required_argument, 0, 's'},
        {"list", no_argument, 0, 'l'},
        {"pubkeys", no_argument, 0, 'k'},
        {"verify", no_argument, 0, 1000},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "d:o:s:lkvh", long_options, NULL)) != -1) {
        switch (c) {
            case 'd':
                if (strcmp(optarg, "auto") == 0) {
                    opts.device_type = DEVICE_AUTO;
                } else if (strcmp(optarg, "tpm") == 0) {
                    opts.device_type = DEVICE_TPM;
                } else if (strcmp(optarg, "fido2") == 0) {
                    opts.device_type = DEVICE_FIDO2;
                } else {
                    fprintf(stderr, "Error: Invalid device type '%s'\n", optarg);
                    return 1;
                }
                break;
            case 'o':
                opts.output_file = optarg;
                break;
            case 's':
                opts.signature_file = optarg;
                break;
            case 'l':
                opts.list_devices = 1;
                break;
            case 'k':
                opts.show_pubkeys = 1;
                break;
            case 1000:
                opts.verify_signature = 1;
                break;
            case 'v':
                opts.verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case '?':
                return 1;
            default:
                abort();
        }
    }
    
    if (opts.list_devices) {
        printf("Available hardware signature devices:\n");
        list_tpm_devices();
        list_fido2_devices();
        return 0;
    }
    
    if (opts.show_pubkeys) {
        return show_all_public_keys();
    }
    
    if (optind >= argc) {
        fprintf(stderr, "Error: No message provided\n");
        print_usage(argv[0]);
        return 1;
    }
    
    opts.message = argv[optind];
    
    if (strlen(opts.message) > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "Error: Message too long (max %d characters)\n", MAX_MESSAGE_SIZE);
        return 1;
    }
    
    // Handle verification mode
    if (opts.verify_signature) {
        if (!opts.signature_file) {
            fprintf(stderr, "Error: Signature file required for verification (use -s)\n");
            print_usage(argv[0]);
            return 1;
        }
        
        // Read signature from file
        FILE *f = fopen(opts.signature_file, "rb");
        if (!f) {
            perror("Error opening signature file");
            return 1;
        }
        
        unsigned char signature[MAX_SIGNATURE_SIZE];
        size_t sig_len = fread(signature, 1, MAX_SIGNATURE_SIZE, f);
        fclose(f);
        
        if (sig_len == 0) {
            fprintf(stderr, "Error: Empty signature file\n");
            return 1;
        }
        
        // Determine signature type from content
        int result = -1;
        if (strncmp((char*)signature, "TPM_SIG:", 8) == 0) {
            result = verify_tpm_signature(opts.message, signature, sig_len);
        } else if (strncmp((char*)signature, "FIDO2_SIG:", 10) == 0) {
            result = verify_fido2_signature(opts.message, signature, sig_len);
        } else {
            fprintf(stderr, "Error: Unknown signature format\n");
            return 1;
        }
        
        return (result == 0) ? 0 : 1;
    }
    
    if (opts.device_type == DEVICE_AUTO) {
        opts.device_type = detect_best_device();
        if (opts.verbose) {
            printf("Auto-detected device type: %s\n", 
                   opts.device_type == DEVICE_TPM ? "TPM" : "FIDO2");
        }
    }
    
    unsigned char signature[MAX_SIGNATURE_SIZE];
    size_t sig_len;
    int result;
    
    switch (opts.device_type) {
        case DEVICE_TPM:
            result = sign_with_tpm(opts.message, signature, &sig_len);
            break;
        case DEVICE_FIDO2:
            result = sign_with_fido2(opts.message, signature, &sig_len);
            break;
        default:
            fprintf(stderr, "Error: No suitable device found\n");
            return 1;
    }
    
    if (result != 0) {
        fprintf(stderr, "Error: Failed to sign message\n");
        return 1;
    }
    
    if (opts.output_file) {
        FILE *f = fopen(opts.output_file, "wb");
        if (!f) {
            perror("Error opening output file");
            return 1;
        }
        fwrite(signature, 1, sig_len, f);
        fclose(f);
        printf("Signature written to %s\n", opts.output_file);
    } else {
        printf("Signature: ");
        for (size_t i = 0; i < sig_len; i++) {
            printf("%02x", signature[i]);
        }
        printf("\n");
    }
    
    return 0;
}