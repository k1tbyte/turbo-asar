//
// Created by kitbyte on 11.11.2025.
//

#ifndef TURBO_ASAR_GLOB_H
#define TURBO_ASAR_GLOB_H
#include <stdbool.h>
#include "defines.h"


/**
 * @brief Shell-style pattern matching, like !fnmatch(pat, str, 0)
 *
 * @param pat: Shell-style pattern to match, e.g. "*.[ch]".
 * @param str: String to match.  The pattern must match the entire string.
 *
 * https://github.com/torvalds/linux/blob/master/lib/glob.c
 *
 * @return: true if  str matches pat, false otherwise.
 *
 */
TURBO_ASAR_API bool __pure glob_match(char const *pat, char const *str);

/**
 * @brief Normalize glob pattern for the current platform
 *
 * @param pat Input pattern, can be NULL
 * @return Normalized pattern (caller must free(pat)) or NULL
 */
TURBO_ASAR_API char* normalize_glob_pattern(const char* pat);

#endif //TURBO_ASAR_GLOB_H
