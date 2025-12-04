/**
 * @file filesystem.c
 * @brief ASAR filesystem header manipulation
 *
 * Created by kitbyte on 08.11.2025.
 */

#include "filesystem.h"
#include "defines.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


#define MAX_PATH_LEN 4096

/* Filesystem context */
struct asar_filesystem {
    char *root_path;
    cJSON *header;
    size_t header_size;
    uint64_t offset;
};

static inline void normalize_path(char *path)
{
#ifdef __WINDOWS__
    for (char *p = path; *p; p++) {
        if (*p == '/') *p = '\\';
    }
#else
    for (char *p = path; *p; p++) {
        if (*p == '\\') *p = '/';
    }
#endif
}

const char* get_relative_path(asar_filesystem_t *fs, const char *path)
{
    const char *root = fs->root_path;
    size_t root_len = strlen(root);
    
    if (strncmp(path, root, root_len) == 0) {
        path += root_len;
        if (*path == PATH_SEPARATOR || *path == '/' || *path == '\\') {
            path++;
        }
    }
    
    return path;
}

/* Find or create node for a path (returns "files" object for directory) */
static cJSON* find_or_create_node(asar_filesystem_t *fs, const char *rel_path, bool create_parent)
{
    cJSON *node = fs->header;
    char *path_copy = strdup(rel_path);
    if (!path_copy) return NULL;
    
    normalize_path(path_copy);
    
    char *token = strtok(path_copy, PATH_SEPARATOR_STR "/\\");
    char *next_token = token ? strtok(NULL, PATH_SEPARATOR_STR "/\\") : NULL;
    
    while (token) {
        if (strcmp(token, ".") == 0) {
            token = next_token;
            next_token = token ? strtok(NULL, PATH_SEPARATOR_STR "/\\") : NULL;
            continue;
        }
        
        /* Get or create "files" object */
        cJSON *files = cJSON_GetObjectItemCaseSensitive(node, "files");
        if (!files) {
            files = cJSON_AddObjectToObject(node, "files");
            if (!files) {
                free(path_copy);
                return NULL;
            }
        }
        
        /* Get or create child node */
        cJSON *child = cJSON_GetObjectItemCaseSensitive(files, token);
        if (!child) {
            if (!create_parent && next_token == NULL) {
                /* Don't create if it's the final component and we're just reading */
            }
            child = cJSON_AddObjectToObject(files, token);
            if (!child) {
                free(path_copy);
                return NULL;
            }
        }
        
        node = child;
        token = next_token;
        next_token = token ? strtok(NULL, PATH_SEPARATOR_STR "/\\") : NULL;
    }
    
    free(path_copy);
    return node;
}

/* Recursively list files */
static bool list_files_recursive(cJSON *node, const char *base_path, char ***files, size_t *count, size_t *capacity)
{
    cJSON *files_obj = cJSON_GetObjectItemCaseSensitive(node, "files");
    if (!files_obj) {
        return true;  /* Leaf node (file or link) */
    }
    
    cJSON *child;
    cJSON_ArrayForEach(child, files_obj) {
        /* Build full path */
        size_t base_len = strlen(base_path);
        size_t name_len = strlen(child->string);
        char *full_path = malloc(base_len + 1 + name_len + 1);
        if (!full_path) return false;
        
        if (base_len > 0) {
            memcpy(full_path, base_path, base_len);
            full_path[base_len] = '/';
            memcpy(full_path + base_len + 1, child->string, name_len + 1);
        } else {
            full_path[0] = '/';
            memcpy(full_path + 1, child->string, name_len + 1);
        }
        
        /* Add to list */
        if (*count >= *capacity) {
            size_t new_capacity = *capacity * 2;
            if (new_capacity < 16) new_capacity = 16;
            char **new_files = realloc(*files, new_capacity * sizeof(char*));
            if (!new_files) {
                free(full_path);
                return false;
            }

            *files = new_files;
            *capacity = new_capacity;
        }

        (*files)[*count] = full_path;
        (*count)++;
        
        /* Recurse into child */
        if (!list_files_recursive(child, full_path, files, count, capacity)) {
            return false;
        }
    }
    
    return true;
}

asar_filesystem_t* asar_filesystem_create(const char *root_path)
{
    asar_filesystem_t *fs = calloc(1, sizeof(asar_filesystem_t));
    if (!fs) return NULL;
    
    fs->root_path = strdup(root_path);
    if (!fs->root_path) {
        free(fs);
        return NULL;
    }
    
    /* Remove trailing separator from root path */
    size_t len = strlen(fs->root_path);
    while (len > 0 && (fs->root_path[len-1] == '/' || fs->root_path[len-1] == '\\')) {
        fs->root_path[--len] = '\0';
    }
    
    fs->header = cJSON_CreateObject();
    if (!fs->header) {
        free(fs->root_path);
        free(fs);
        return NULL;
    }
    
    /* Add root "files" object */
    if (!cJSON_AddObjectToObject(fs->header, "files")) {
        cJSON_Delete(fs->header);
        free(fs->root_path);
        free(fs);
        return NULL;
    }
    
    fs->header_size = 0;
    fs->offset = 0;
    
    return fs;
}

void asar_filesystem_free(asar_filesystem_t *fs)
{
    if (!fs) return;
    
    if (fs->root_path) {
        free(fs->root_path);
    }
    if (fs->header) {
        cJSON_Delete(fs->header);
    }
    free(fs);
}

const char* asar_filesystem_get_root(asar_filesystem_t *fs)
{
    return fs ? fs->root_path : NULL;
}

uint64_t asar_filesystem_get_offset(asar_filesystem_t *fs)
{
    return fs ? fs->offset : 0;
}

size_t asar_filesystem_get_header_size(asar_filesystem_t *fs)
{
    return fs ? fs->header_size : 0;
}

void asar_filesystem_set_header(asar_filesystem_t *fs, cJSON *header, size_t header_size)
{
    if (!fs) return;
    
    if (fs->header) {
        cJSON_Delete(fs->header);
    }
    fs->header = header;
    fs->header_size = header_size;
}

cJSON* asar_filesystem_get_header(asar_filesystem_t *fs)
{
    return fs ? fs->header : NULL;
}

bool asar_filesystem_insert_directory(asar_filesystem_t *fs, const char *rel_path, bool unpacked)
{
    if (!fs) return false;

    if (!rel_path || !*rel_path) {
        /* Root directory already exists */
        return true;
    }
    
    cJSON *node = find_or_create_node(fs, rel_path, true);
    if (!node) return false;

    if (unpacked) {
        cJSON_AddBoolToObject(node, "unpacked", true);
    }
    
    /* Ensure "files" object exists */
    if (!cJSON_GetObjectItemCaseSensitive(node, "files")) {
        if (!cJSON_AddObjectToObject(node, "files")) {
            return false;
        }
    }
    
    return true;
}

bool asar_filesystem_insert_file(
    asar_filesystem_t *fs,
    const char *rel_path,
    uint64_t size,
    bool executable,
    bool unpacked,
    const char *integrity_hash,
    const char **block_hashes,
    size_t block_count,
    uint32_t block_size
)
{
    if (!fs || !rel_path) return false;

    cJSON *node = find_or_create_node(fs, rel_path, true);
    if (!node) return false;
    
    /* Add file properties */
    cJSON_AddNumberToObject(node, "size", (double)size);
    
    if (unpacked) {
        cJSON_AddBoolToObject(node, "unpacked", true);
    } else {
        /* Convert offset to string as per asar format */
        char offset_str[32];
        snprintf(offset_str, sizeof(offset_str), "%llu", (unsigned long long)fs->offset);
        cJSON_AddStringToObject(node, "offset", offset_str);
        fs->offset += size;
    }
    
    if (executable) {
        cJSON_AddBoolToObject(node, "executable", true);
    }
    
    /* Add integrity info if provided */
    if (integrity_hash && block_hashes && block_count > 0) {
        cJSON *integrity = cJSON_AddObjectToObject(node, "integrity");
        if (integrity) {
            cJSON_AddStringToObject(integrity, "algorithm", "SHA256");
            cJSON_AddStringToObject(integrity, "hash", integrity_hash);
            cJSON_AddNumberToObject(integrity, "blockSize", (double)block_size);
            
            cJSON *blocks = cJSON_AddArrayToObject(integrity, "blocks");
            if (blocks) {
                for (size_t i = 0; i < block_count; i++) {
                    cJSON_AddItemToArray(blocks, cJSON_CreateString(block_hashes[i]));
                }
            }
        }
    }
    
    return true;
}

bool asar_filesystem_insert_link(
    asar_filesystem_t *fs,
    const char *rel_path,
    const char *link_target,
    bool unpacked
)
{
    if (!fs || !rel_path || !link_target) return false;

    cJSON *node = find_or_create_node(fs, rel_path, true);
    if (!node) return false;
    
    cJSON_AddStringToObject(node, "link", link_target);
    
    if (unpacked) {
        cJSON_AddBoolToObject(node, "unpacked", true);
    }
    
    return true;
}

bool asar_filesystem_get_entry(
    asar_filesystem_t *fs,
    const char *path,
    bool follow_links,
    asar_entry_info_t *info
)
{
    if (!fs || !path || !info) return false;
    
    memset(info, 0, sizeof(*info));
    
    /* Skip leading slash/separator */
    while (*path == '/' || *path == '\\') path++;
    
    cJSON *node = fs->header;
    if (*path) {
        char *path_copy = strdup(path);
        if (!path_copy) return false;
        normalize_path(path_copy);
        
        char *token = strtok(path_copy, PATH_SEPARATOR_STR "/\\");
        while (token) {
            cJSON *files = cJSON_GetObjectItemCaseSensitive(node, "files");
            if (!files) {
                free(path_copy);
                return false;
            }
            
            node = cJSON_GetObjectItemCaseSensitive(files, token);
            if (!node) {
                free(path_copy);
                return false;
            }
            
            token = strtok(NULL, PATH_SEPARATOR_STR "/\\");
        }
        free(path_copy);
    }
    
    /* Check for link */
    cJSON *link = cJSON_GetObjectItemCaseSensitive(node, "link");
    if (link && cJSON_IsString(link)) {
        if (follow_links) {
            return asar_filesystem_get_entry(fs, link->valuestring, true, info);
        }
        info->type = ASAR_ENTRY_LINK;
        info->link = strdup(link->valuestring);
        info->unpacked = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(node, "unpacked"));
        return true;
    }
    
    /* Check for directory */
    cJSON *files = cJSON_GetObjectItemCaseSensitive(node, "files");
    if (files) {
        info->type = ASAR_ENTRY_DIRECTORY;
        info->unpacked = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(node, "unpacked"));
        return true;
    }
    
    /* It's a file */
    info->type = ASAR_ENTRY_FILE;
    
    cJSON *size_item = cJSON_GetObjectItemCaseSensitive(node, "size");
    if (size_item && cJSON_IsNumber(size_item)) {
        info->size = (uint64_t)size_item->valuedouble;
    }
    
    cJSON *offset_item = cJSON_GetObjectItemCaseSensitive(node, "offset");
    if (offset_item && cJSON_IsString(offset_item)) {
        char *endptr;
        info->offset = strtoull(offset_item->valuestring, &endptr, 10);
        /* If parsing failed (no digits consumed), offset remains 0 */
        if (endptr == offset_item->valuestring) {
            info->offset = 0;
        }
    }
    
    info->unpacked = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(node, "unpacked"));
    info->executable = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(node, "executable"));
    
    /* Parse integrity info */
    cJSON *integrity = cJSON_GetObjectItemCaseSensitive(node, "integrity");
    if (!integrity) {
        return true;
    }

    cJSON *hash = cJSON_GetObjectItemCaseSensitive(integrity, "hash");
    if (hash && cJSON_IsString(hash)) {
        info->integrity_hash = strdup(hash->valuestring);
    }

    cJSON *block_size = cJSON_GetObjectItemCaseSensitive(integrity, "blockSize");
    if (block_size && cJSON_IsNumber(block_size)) {
        info->integrity_block_size = (uint32_t)block_size->valuedouble;
    }

    cJSON *blocks = cJSON_GetObjectItemCaseSensitive(integrity, "blocks");

    if (!blocks || !cJSON_IsArray(blocks)) {
        return true;
    }

    int block_count = cJSON_GetArraySize(blocks);

    if (!block_count) {
        return true;
    }

    info->integrity_blocks = malloc(block_count * sizeof(char*));

    if (!info->integrity_blocks) {
        return false;
    }

    info->integrity_block_count = (size_t)block_count;
    for (int i = 0; i < block_count; i++) {
        cJSON *block = cJSON_GetArrayItem(blocks, i);
        info->integrity_blocks[i] = block && cJSON_IsString(block) ? strdup(block->valuestring) : NULL;
    }
    
    return true;
}

void asar_entry_info_free(asar_entry_info_t *info)
{
    if (!info) return;
    
    if (info->link) {
        free(info->link);
        info->link = NULL;
    }
    if (info->integrity_hash) {
        free(info->integrity_hash);
        info->integrity_hash = NULL;
    }
    if (info->integrity_blocks) {
        for (size_t i = 0; i < info->integrity_block_count; i++) {
            free(info->integrity_blocks[i]);
        }
        free(info->integrity_blocks);
        info->integrity_blocks = NULL;
    }
}

bool asar_filesystem_list_files(
    asar_filesystem_t *fs,
    char ***files,
    size_t *count
)
{
    if (!fs || !files || !count) return false;
    
    *files = NULL;
    *count = 0;
    size_t capacity = 0;
    
    return list_files_recursive(fs->header, "", files, count, &capacity);
}

bool asar_filesystem_serialize_header(asar_filesystem_t *fs, char **json_str)
{
    if (!fs || !json_str) return false;
    
    *json_str = cJSON_PrintUnformatted(fs->header);
    return *json_str != NULL;
}
