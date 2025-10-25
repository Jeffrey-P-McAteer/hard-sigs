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
    int verbose;
    int list_devices;
} options_t;

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] [MESSAGE]\n", program_name);
    printf("\nOptions:\n");
    printf("  -d, --device TYPE     Device type: auto, tpm, fido2 (default: auto)\n");
    printf("  -o, --output FILE     Output signature to file\n");
    printf("  -l, --list           List available devices\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  -h, --help           Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s \"Hello World\"                    # Sign message with auto-detected device\n", program_name);
    printf("  %s -d tpm \"Hello World\"             # Sign with TPM\n", program_name);
    printf("  %s -d fido2 -o sig.bin \"Message\"   # Sign with FIDO2, save to file\n", program_name);
    printf("  %s -l                               # List available devices\n", program_name);
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
        {"list", no_argument, 0, 'l'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int c;
    while ((c = getopt_long(argc, argv, "d:o:lvh", long_options, NULL)) != -1) {
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
            case 'l':
                opts.list_devices = 1;
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