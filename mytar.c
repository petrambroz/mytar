#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#define BLOCK_SIZE 512
#define USTAR_MAGIC "ustar"


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
                    free(args.file_arguments);
                    errx(2, "option requires an argument -- 'f'");
                }
                args.archive_name = argv[i];
                break;
            default:
                free(args.file_arguments);
                errx(2, "Unknown option: -%c", argv[i][1]);
        }
    }

    if (!found_operation) {
        free(args.file_arguments);
        errx(2, "need at least one option");
    }

    if (!args.archive_name && found_operation) {
        free(args.file_arguments);
        errx(2, "option requires an argument -- 'f'");
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
        errx(2, "Invalid magic number in tar header");
    }

    // Only support regular files (type '0' or '\0')
    char type = header->typeflag;
    if (type != '0' && type != '\0') {
        errx(2, "Unsupported header type: %d", type);
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

void skip_file_content(FILE *archive, const tar_header *header) {
    unsigned long long size = get_size(header->size);
    unsigned long long blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;

    // Try reading block by block to detect truncation
    char buffer[BLOCK_SIZE];
    for (unsigned long long i = 0; i < blocks; i++) {
        if (fread(buffer, 1, BLOCK_SIZE, archive) != BLOCK_SIZE) {
            warnx("Unexpected EOF in archive");
            errx(2, "Error is not recoverable: exiting now");
        }
    }
}

void process_file_arguments(const char *filename, file_status *files, int num_files) {
    if (num_files == 0) {
        printf("%s\n", filename);
        return;
    }

    for (int i = 0; i < num_files; i++) {
        if (strcmp(filename, files[i].name) == 0) {
            printf("%s\n", filename);
            files[i].found = 1;
            return;
        }
    }
}

int list(arguments args) {
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
            errx(1, "memory allocation failed");
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

        // Process this header
        validate_header(&header);
        process_file_arguments(header.name, files, args.num_file_arguments);

        // Skip file content and update block counter
        unsigned long long file_blocks = (get_size(header.size) + BLOCK_SIZE - 1) / BLOCK_SIZE;
        skip_file_content(archive, &header);

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
        ret = list(args);
    } else if (args.extract_flag) {
        // ret = extract(args);
    }

    free(args.file_arguments);
    return ret;
}