/**
 * @file main.c
 * @brief Turbo ASAR command line tool
 *
 * Created by kitbyte on 12.11.2025.
 */

#include "turbo_asar.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *prog_name)
{
    printf("turbo-asar v%s - High-performance ASAR archive tool\n\n", turbo_asar_version());
    printf("Usage:\n");
    printf("  %s pack <dir> <output.asar>     Create archive from directory\n", prog_name);
    printf("  %s extract <archive> <dest>     Extract archive to directory\n", prog_name);
    printf("  %s list <archive>               List files in archive\n", prog_name);
    printf("  %s extract-file <archive> <file> [output]\n", prog_name);
    printf("                                    Extract single file from archive\n");
    printf("\nOptions:\n");
    printf("  --no-integrity    Skip integrity calculation when packing\n");
    printf("  --exclude-hidden  Exclude hidden files (starting with .)\n");
    printf("  --help            Show this help message\n");
    printf("  --version         Show version\n");
}

static void print_version(void)
{
    printf("turbo-asar v%s\n", turbo_asar_version());
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    /* Check for options */
    turbo_asar_pack_options_t options = {0};
    options.calculate_integrity = true;
    
    int arg_start = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            print_version();
            return 0;
        }
        if (strcmp(argv[i], "--no-integrity") == 0) {
            options.calculate_integrity = false;
            arg_start = i + 1;
        }
        if (strcmp(argv[i], "--exclude-hidden") == 0) {
            options.exclude_hidden = true;
            arg_start = i + 1;
        }
    }
    
    /* Find command position (skip options) */
    int cmd_idx = arg_start;
    while (cmd_idx < argc && argv[cmd_idx][0] == '-') {
        cmd_idx++;
    }
    
    if (cmd_idx >= argc) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *command = argv[cmd_idx];
    turbo_asar_error_t err;
    
    /* Pack command */
    if (strcmp(command, "pack") == 0 || strcmp(command, "p") == 0) {
        if (cmd_idx + 2 >= argc) {
            fprintf(stderr, "Error: pack requires <dir> and <output.asar>\n");
            return 1;
        }
        
        const char *src_dir = argv[cmd_idx + 1];
        const char *dest = argv[cmd_idx + 2];
        
        printf("Packing %s -> %s\n", src_dir, dest);
        err = turbo_asar_pack(src_dir, dest, &options);
        
        if (err != TURBO_ASAR_OK) {
            fprintf(stderr, "Error: %s\n", turbo_asar_strerror(err));
            return 1;
        }
        
        printf("Done.\n");
        return 0;
    }
    
    /* Extract command */
    if (strcmp(command, "extract") == 0 || strcmp(command, "e") == 0) {
        if (cmd_idx + 2 >= argc) {
            fprintf(stderr, "Error: extract requires <archive> and <dest>\n");
            return 1;
        }
        
        const char *archive = argv[cmd_idx + 1];
        const char *dest = argv[cmd_idx + 2];
        
        printf("Extracting %s -> %s\n", archive, dest);
        err = turbo_asar_extract_all(archive, dest);
        
        if (err != TURBO_ASAR_OK) {
            fprintf(stderr, "Error: %s\n", turbo_asar_strerror(err));
            return 1;
        }
        
        printf("Done.\n");
        return 0;
    }
    
    /* List command */
    if (strcmp(command, "list") == 0 || strcmp(command, "l") == 0) {
        if (cmd_idx + 1 >= argc) {
            fprintf(stderr, "Error: list requires <archive>\n");
            return 1;
        }
        
        const char *archive = argv[cmd_idx + 1];
        
        char **files;
        size_t count;
        err = turbo_asar_list(archive, &files, &count);
        
        if (err != TURBO_ASAR_OK) {
            fprintf(stderr, "Error: %s\n", turbo_asar_strerror(err));
            return 1;
        }
        
        for (size_t i = 0; i < count; i++) {
            printf("%s\n", files[i]);
        }
        
        turbo_asar_free_list(files, count);
        return 0;
    }
    
    /* Extract-file command */
    if (strcmp(command, "extract-file") == 0 || strcmp(command, "ef") == 0) {
        if (cmd_idx + 2 >= argc) {
            fprintf(stderr, "Error: extract-file requires <archive> and <file>\n");
            return 1;
        }
        
        const char *archive = argv[cmd_idx + 1];
        const char *file_path = argv[cmd_idx + 2];
        const char *output = cmd_idx + 3 < argc ? argv[cmd_idx + 3] : NULL;
        
        uint8_t *buffer;
        size_t size;
        err = turbo_asar_extract_file(archive, file_path, &buffer, &size);
        
        if (err != TURBO_ASAR_OK) {
            fprintf(stderr, "Error: %s\n", turbo_asar_strerror(err));
            return 1;
        }
        
        if (output) {
            /* Write to file */
            FILE *fp = fopen(output, "wb");
            if (!fp) {
                fprintf(stderr, "Error: Cannot open output file\n");
                free(buffer);
                return 1;
            }
            fwrite(buffer, 1, size, fp);
            fclose(fp);
            printf("Extracted %s (%zu bytes)\n", file_path, size);
        } else {
            /* Write to stdout */
            fwrite(buffer, 1, size, stdout);
        }
        
        free(buffer);
        return 0;
    }
    
    fprintf(stderr, "Unknown command: %s\n", command);
    print_usage(argv[0]);
    return 1;
}
