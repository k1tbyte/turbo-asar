/**
 * @file filesystem.h
 * @brief ASAR filesystem header manipulation
 *
 * Created by kitbyte on 08.11.2025.
 */

#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {

#endif

typedef struct asar_filesystem asar_filesystem_t;

typedef enum {
    ASAR_ENTRY_FILE,
    ASAR_ENTRY_DIRECTORY,
    ASAR_ENTRY_LINK
} asar_entry_type_t;

typedef struct {
    asar_entry_type_t type;
    uint64_t size;
    uint64_t offset;
    bool unpacked;
    bool executable;
    char *link; /* For symlinks, relative path to target */
    /* Integrity info */
    char *integrity_hash;
    uint32_t integrity_block_size;
    char **integrity_blocks;
    size_t integrity_block_count;
} asar_entry_info_t;

/**
 * Create a new filesystem context
 */
asar_filesystem_t *asar_filesystem_create(const char *root_path);

/**
 * Free filesystem context
 */
void asar_filesystem_free(asar_filesystem_t *fs);

const char *asar_filesystem_get_root(asar_filesystem_t *fs);

/**
 * Get current offset for file data
 */
uint64_t asar_filesystem_get_offset(asar_filesystem_t *fs);

/**
 * Get header size (after finalization)
 */
size_t asar_filesystem_get_header_size(asar_filesystem_t *fs);

/**
 * Set header from parsed JSON (for reading archives)
 * 
 * @param fs Filesystem context
 * @param header cJSON object (ownership transferred to fs)
 * @param header_size Size of header data
 */
void asar_filesystem_set_header(asar_filesystem_t *fs, cJSON *header, size_t header_size);

/**
 * Get header JSON object
 */
cJSON *asar_filesystem_get_header(asar_filesystem_t *fs);

/**
 * Insert a directory entry
 * 
 * @param fs Filesystem context
 * @param path Full path to directory
 * @param unpacked Whether directory contents should be unpacked
 */
bool asar_filesystem_insert_directory(asar_filesystem_t *fs, const char *path, bool unpacked);

/**
 * Insert a file entry
 * 
 * @param fs Filesystem context
 * @param path Full path to file
 * @param size File size
 * @param executable Whether file is executable
 * @param unpacked Whether file should be unpacked
 * @param integrity_hash SHA256 hash of file (can be NULL)
 * @param block_hashes Array of block hashes (can be NULL)
 * @param block_count Number of block hashes
 * @param block_size Block size used for hashing
 */
bool asar_filesystem_insert_file(
    asar_filesystem_t *fs,
    const char *path,
    uint64_t size,
    bool executable,
    bool unpacked,
    const char *integrity_hash,
    const char **block_hashes,
    size_t block_count,
    uint32_t block_size
);

/**
 * Insert a symlink entry
 */
bool asar_filesystem_insert_link(
    asar_filesystem_t *fs,
    const char *path,
    const char *link_target,
    bool unpacked
);

/**
 * Get entry info for a path
 * 
 * @param fs Filesystem context
 * @param path Path within archive (without leading /)
 * @param follow_links Whether to follow symlinks
 * @param info Output entry info (caller must free strings)
 * @return true if found
 */
bool asar_filesystem_get_entry(
    asar_filesystem_t *fs,
    const char *path,
    bool follow_links,
    asar_entry_info_t *info
);

/**
 * Free entry info strings
 */
void asar_entry_info_free(asar_entry_info_t *info);

/**
 * List all files in filesystem
 * 
 * @param fs Filesystem context
 * @param files Output array of paths (caller must free)
 * @param count Output count
 * @return true on success
 */
bool asar_filesystem_list_files(
    asar_filesystem_t *fs,
    char ***files,
    size_t *count
);

/**
 * Serialize header to JSON string
 * 
 * @param fs Filesystem context
 * @param json_str Output JSON string (caller must free with cJSON_free)
 * @return true on success
 */
bool asar_filesystem_serialize_header(asar_filesystem_t *fs, char **json_str);

const char *get_relative_path(asar_filesystem_t *fs, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* FILESYSTEM_H */
