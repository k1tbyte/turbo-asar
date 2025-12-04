/**
 * @file turbo_asar.h
 * @brief Turbo ASAR - High-performance ASAR archive library
 *
 * Created by kitbyte on 08.11.2025.
 */

#ifndef TURBO_ASAR_H
#define TURBO_ASAR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "defines.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    TURBO_ASAR_OK                       = 0,
    TURBO_ASAR_ERR_NULL_PARAM           = -1,
    TURBO_ASAR_ERR_FILE_NOT_FOUND       = -2,
    TURBO_ASAR_ERR_FILE_READ            = -3,
    TURBO_ASAR_ERR_FILE_WRITE           = -4,
    TURBO_ASAR_ERR_INVALID_ARCHIVE      = -5,
    TURBO_ASAR_ERR_INVALID_HEADER       = -6,
    TURBO_ASAR_ERR_OUT_OF_MEMORY        = -7,
    TURBO_ASAR_ERR_PATH_TOO_LONG        = -8,
    TURBO_ASAR_ERR_MKDIR_FAILED         = -9,
    TURBO_ASAR_ERR_JSON_PARSE           = -10,
    TURBO_ASAR_ERR_NOT_FOUND_IN_ARCHIVE = -11,
    TURBO_ASAR_ERR_IS_DIRECTORY         = -12,
    TURBO_ASAR_ERR_SYMLINK_OUTSIDE      = -13,
} turbo_asar_error_t;

typedef enum {
    TURBO_ASAR_ENTRY_FILE,
    TURBO_ASAR_ENTRY_DIRECTORY,
    TURBO_ASAR_ENTRY_LINK
} turbo_asar_entry_type_t;

typedef struct {
    char algorithm[16];     /* e.g. "sha256" */
    char hash[65];          /* Hex-encoded hash */
    uint32_t block_size;
    char **blocks;          /* Array of block hashes */
    size_t block_count;
} turbo_asar_integrity_t;

typedef struct {
    turbo_asar_entry_type_t type;
    uint64_t size;
    uint64_t offset;
    bool unpacked;
    bool executable;
    char *link;             /* For symlinks only */
    turbo_asar_integrity_t *integrity;
} turbo_asar_entry_t;

typedef struct turbo_asar_archive turbo_asar_archive_t;

typedef struct {
    const char *unpack;          /* Glob pattern for files to unpack */
    bool calculate_integrity;    /* Calculate SHA256 integrity for files */
    bool exclude_hidden;         /* Exclude hidden files (starting with .) */
} turbo_asar_pack_options_t;

/* ----- Core API ----- */

TURBO_ASAR_API const char* turbo_asar_version(void);

/**
 * Get human-readable error message for error code
 */
TURBO_ASAR_API const char* turbo_asar_strerror(turbo_asar_error_t err);

/**
 * Create an ASAR archive from a directory
 * 
 * @param src_dir Source directory path
 * @param dest_path Destination archive path
 * @param options Pack options (can be NULL for defaults)
 * @return TURBO_ASAR_OK on success, error code on failure
 */
TURBO_ASAR_API turbo_asar_error_t turbo_asar_pack(
    const char *src_dir,
    const char *dest_path,
    const turbo_asar_pack_options_t *options
);

/**
 * Extract entire ASAR archive to a directory
 * 
 * @param archive_path Path to the ASAR archive
 * @param dest_dir Destination directory path
 * @return TURBO_ASAR_OK on success, error code on failure
 */
TURBO_ASAR_API turbo_asar_error_t turbo_asar_extract_all(
    const char *archive_path,
    const char *dest_dir
);

/**
 * Extract a single file from ASAR archive
 * 
 * @param archive_path Path to the ASAR archive
 * @param file_path Path within the archive
 * @param buffer Output buffer (caller must free)
 * @param size Output size
 * @return TURBO_ASAR_OK on success, error code on failure
 */
TURBO_ASAR_API turbo_asar_error_t turbo_asar_extract_file(
    const char *archive_path,
    const char *file_path,
    uint8_t **buffer,
    size_t *size
);

/**
 * List files in ASAR archive
 * 
 * @param archive_path Path to the ASAR archive
 * @param files Output array of file paths (caller must free each string and array)
 * @param count Output number of files
 * @return TURBO_ASAR_OK on success, error code on failure
 */
TURBO_ASAR_API turbo_asar_error_t turbo_asar_list(
    const char *archive_path,
    char ***files,
    size_t *count
);

/**
 * Get raw header JSON from ASAR archive
 * 
 * @param archive_path Path to the ASAR archive
 * @param header_json Output JSON string (caller must free)
 * @return TURBO_ASAR_OK on success, error code on failure
 */
TURBO_ASAR_API turbo_asar_error_t turbo_asar_get_header(
    const char *archive_path,
    char **header_json
);

/**
 * Get file information from ASAR archive
 * 
 * @param archive_path Path to the ASAR archive  
 * @param file_path Path within the archive
 * @param entry Output entry information (caller must free entry->link and entry->integrity)
 * @return TURBO_ASAR_OK on success, error code on failure
 */
TURBO_ASAR_API turbo_asar_error_t turbo_asar_stat(
    const char *archive_path,
    const char *file_path,
    turbo_asar_entry_t *entry
);


TURBO_ASAR_API void turbo_asar_free_list(char **files, size_t count);
TURBO_ASAR_API void turbo_asar_free_entry(turbo_asar_entry_t *entry);
TURBO_ASAR_API void turbo_asar_free_integrity(turbo_asar_integrity_t *integrity);

#ifdef __cplusplus
}
#endif

#endif /* TURBO_ASAR_H */
