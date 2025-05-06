#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#define BLOCK_SIZE 512
#define USTAR_MAGIC "ustar"

#define ERROR_MEMORY 1
#define ERROR_ARGS 2
#define ZERO_BLOCKS_REQUIRED 2

typedef struct {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char chksum[8];
    char typeflag;
    char linkname[100];
    char magic[6];
    char version[2];
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
} tar_header;

typedef struct {
    char *archive_name;
    int list_flag;
    int extract_flag;
    int verbose_flag;
    char **file_arguments;
    int num_file_arguments;
} arguments;

typedef struct {
    char *name;
    int found;
} file_status;

void cleanup_args(arguments *args) {
    if (args->file_arguments) {
        free(args->file_arguments);
        args->file_arguments = NULL;
    }
}

arguments parse_arguments(int argc, char *argv[]) {
    arguments args = {NULL, 0, 0, 0, NULL, 0};

    if (argc < 2) {
        errx(2, "need at least one option");
    }

    args.file_arguments = malloc(sizeof(char *) * argc);
    if (!args.file_arguments) {
        errx(1, "memory allocation failed");
    }

    int found_operation = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-' || argv[i][1] == '\0') {
            args.file_arguments[args.num_file_arguments++] = argv[i];
            continue;
        }

        switch (argv[i][1]) {
            case 't':
                args.list_flag = 1;
                found_operation = 1;
                break;
            case 'x':
                args.extract_flag = 1;
                found_operation = 1;
                break;
            case 'v':
                args.verbose_flag = 1;
                break;
            case 'f':
                if (++i >= argc) {
                    cleanup_args(&args);
                    errx(ERROR_ARGS, "option requires an argument -- 'f'");
                }
                args.archive_name = argv[i];
                break;
            default:
                cleanup_args(&args);
                errx(ERROR_ARGS, "Unknown option: -%c", argv[i][1]);
        }
    }

    if (!found_operation) {
        cleanup_args(&args);
        errx(ERROR_ARGS, "need at least one option");
    }

    if (!args.archive_name && found_operation) {
        cleanup_args(&args);
        errx(ERROR_ARGS, "option requires an argument -- 'f'");
    }

    return args;
}

unsigned long long base256_to_ull(const char *size_field) {
    unsigned long long val = 0;
    // Process remaining 11 bytes for 12-byte field
    for (int i = 1; i < 12; i++) {
        val = (val << 8) | (unsigned char)size_field[i];
    }
    return val;
}

unsigned long long get_size(const char *size_field) {
    // Check if it's a base-256 number (high bit set)
    if ((size_field[0] & 0x80) != 0) {
        return base256_to_ull(size_field);
    }

    // Regular octal number
    unsigned long long val = 0;
    sscanf(size_field, "%11llo", &val);
    return val;
}

int is_zero_block(const char *block) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        if (block[i] != '\0') {
            return 0;
        }
    }
    return 1;
}

int validate_header(const tar_header *header) {
    // Verify if it's a valid tar header
    if (strncmp(header->magic, USTAR_MAGIC, 5) != 0) {
        return 1;
    }

    // Only support regular files (type '0' or '\0')
    char type = header->typeflag;
    if (type != '0' && type != '\0') {
        errx(2, "Unsupported header type: %d", (int)type);
    }

    return 0;
}

int read_header(FILE *archive, tar_header *header) {
    size_t bytes_read = fread(header, 1, BLOCK_SIZE, archive);
    if (bytes_read != BLOCK_SIZE) {
        return 0;
    }
    return 1;
}

unsigned long long calculate_blocks(unsigned long long size) {
    return (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
}

void skip_file_content(FILE *archive, const tar_header *header) {
    unsigned long long size = get_size(header->size);
    unsigned long long blocks = calculate_blocks(size);

    // Try reading block by block to detect truncation
    char buffer[BLOCK_SIZE];
    for (unsigned long long i = 0; i < blocks; i++) {
        if (fread(buffer, 1, BLOCK_SIZE, archive) != BLOCK_SIZE) {
            warnx("Unexpected EOF in archive");
            errx(2, "Error is not recoverable: exiting now");
        }
    }
}

// Function to check if a file should be processed based on file arguments
int should_process_file(const char *filename, file_status *files, int num_files) {
    // If no specific files were requested, process all files
    if (num_files == 0) {
        return 1;
    }

    // Otherwise, process only if the file was requested
    for (int i = 0; i < num_files; i++) {
        if (strcmp(filename, files[i].name) == 0) {
            files[i].found = 1;
            return 1;
        }
    }

    return 0;
}

// Function to extract file content
int extract_file(FILE *archive, const tar_header *header, int verbose, file_status *files, int num_files) {
    const char *filename = header->name;
    unsigned long long size = get_size(header->size);
    unsigned long long blocks = calculate_blocks(size);

    // Check if we should process this file
    if (!should_process_file(filename, files, num_files)) {
        // Skip this file and return
        fseek(archive, blocks * BLOCK_SIZE, SEEK_CUR);
        return 0;
    }

    // Print filename if verbose
    if (verbose) {
        printf("%s\n", filename);
    }

    // Create and open output file
    FILE *output = fopen(filename, "wb");
    if (!output) {
        warn("Cannot create file %s", filename);
        // Skip this file's blocks
        fseek(archive, blocks * BLOCK_SIZE, SEEK_CUR);
        return 1;
    }

    // Extract file content
    char buffer[BLOCK_SIZE];
    unsigned long long remaining = size;

    for (unsigned long long i = 0; i < blocks; i++) {
        size_t bytes_read = fread(buffer, 1, BLOCK_SIZE, archive);

        if (bytes_read != BLOCK_SIZE) {
            fclose(output);
            warnx("Unexpected EOF in archive");
            errx(2, "Error is not recoverable: exiting now");
        }

        // Write only the required bytes from the last block
        size_t bytes_to_write = (remaining > BLOCK_SIZE) ? BLOCK_SIZE : remaining;
        if (fwrite(buffer, 1, bytes_to_write, output) != bytes_to_write) {
            fclose(output);
            warn("Failed to write to file %s", filename);
            return 1;
        }

        remaining -= bytes_to_write;
    }

    fclose(output);
    return 0;
}

int process_archive(arguments args, int extract_mode) {
    FILE *archive = fopen(args.archive_name, "rb");
    if (!archive) {
        err(2, "Cannot open archive %s", args.archive_name);
    }

    // Setup file tracking if specific files were requested
    file_status *files = NULL;
    if (args.num_file_arguments > 0) {
        files = malloc(sizeof(file_status) * args.num_file_arguments);
        if (!files) {
            fclose(archive);
            errx(ERROR_MEMORY, "memory allocation failed");
        }

        // Initialize file status tracking
        for (int i = 0; i < args.num_file_arguments; i++) {
            files[i].name = args.file_arguments[i];
            files[i].found = 0;
        }
    }

    tar_header header;
    long block_num = 1;
    int zero_blocks = 0;
    int ret = 0;

    // Read and process each header in the archive
    while (read_header(archive, &header)) {
        // Check for zero block
        if (is_zero_block((char *)&header)) {
            zero_blocks++;

            if (zero_blocks == 2) {
                break;
            }

            block_num++;
            continue;
        }

        if (zero_blocks == 1) {
            warnx("A lone zero block at %ld", block_num - 1);
        }
        zero_blocks = 0;

        // Process this header - Check return value from validate_header
        if (validate_header(&header) != 0) {
            warnx("This does not look like a tar archive");
            warnx("Exiting with failure status due to previous errors");
            ret = 2;
            break;
        }

        if (extract_mode) {
            // Extract the file
            extract_file(archive, &header, args.verbose_flag, files, args.num_file_arguments);
        } else {
            // List mode
            if (should_process_file(header.name, files, args.num_file_arguments)) {
                printf("%s\n", header.name);
            }
            // Skip the file content since we're just listing
            skip_file_content(archive, &header);
        }
        unsigned long long file_blocks = (get_size(header.size) + BLOCK_SIZE - 1) / BLOCK_SIZE;
        block_num += file_blocks + 1;
    }

    if (zero_blocks == 1) {
        warnx("A lone zero block at %ld", block_num - 1);
    } else if (zero_blocks == 0) {
        ret = 2;
    }

    // Check for missing requested files
    if (files) {
        int missing_files = 0;

        for (int i = 0; i < args.num_file_arguments; i++) {
            if (!files[i].found) {
                warnx("%s: Not found in archive", files[i].name);
                missing_files = 1;
            }
        }

        if (missing_files) {
            warnx("Exiting with failure status due to previous errors");
            ret = 2;
        }

        free(files);
    }

    fclose(archive);
    return ret;
}

int main(int argc, char *argv[]) {
    arguments args = parse_arguments(argc, argv);
    int ret = 0;

    if (args.list_flag) {
        ret = process_archive(args, 0);
    } else if (args.extract_flag) {
        ret = process_archive(args, 1);
    }

    cleanup_args(&args);
    return ret;
}