/**
 * @file pickle.h
 * @brief Chromium Pickle serialization format
 * 
 * The Pickle format is used by ASAR for binary serialization.
 * It's a simple format with a 4-byte header containing payload size,
 * followed by aligned data.
 *
 * https://github.com/electron/asar/blob/main/src/pickle.ts
 *
 * Created by kitbyte on 08.11.2025.
 */

#ifndef PICKLE_H
#define PICKLE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PICKLE_ALIGN 4

typedef struct {
    const uint8_t *data;
    size_t data_size;
    size_t header_size;
    size_t payload_size;
    size_t read_offset;
} pickle_reader_t;

typedef struct {
    uint8_t *data;
    size_t capacity;
    size_t header_size;
    size_t write_offset;
} pickle_writer_t;

/* ----- Reader API ----- */

/**
 * Initialize pickle reader from buffer
 * 
 * @param reader Pickle reader context
 * @param data Buffer containing pickle data
 * @param size Size of buffer
 * @return true on success, false on invalid data
 */
bool pickle_reader_init(pickle_reader_t *reader, const uint8_t *data, size_t size);

bool pickle_read_uint32(pickle_reader_t *reader, uint32_t *value);
bool pickle_read_int32(pickle_reader_t *reader, int32_t *value);

/**
 * Read a string (length-prefixed)
 * 
 * @param reader Pickle reader context
 * @param str Output string pointer (points into pickle data, not copied)
 * @param len Output string length
 * @return true on success
 */
bool pickle_read_string(pickle_reader_t *reader, const char **str, size_t *len);

/**
 * Read a string and copy it (caller must free)
 */
bool pickle_read_string_copy(pickle_reader_t *reader, char **str);

/* ----- Writer API ----- */

bool pickle_writer_init(pickle_writer_t *writer);

void pickle_writer_free(pickle_writer_t *writer);

bool pickle_write_uint32(pickle_writer_t *writer, uint32_t value);

bool pickle_write_int32(pickle_writer_t *writer, int32_t value);

/**
 * Write a string (length-prefixed)
 */
bool pickle_write_string(pickle_writer_t *writer, const char *str, size_t len);

/**
 * Get the final pickle buffer
 * 
 * @param writer Pickle writer context
 * @param size Output buffer size
 * @return Pointer to pickle data (owned by writer, valid until free)
 */
const uint8_t* pickle_writer_data(pickle_writer_t *writer, size_t *size);

/**
 * Copy the final pickle buffer (caller must free)
 */
uint8_t* pickle_writer_copy(pickle_writer_t *writer, size_t *size);

#ifdef __cplusplus
}
#endif

#endif /* PICKLE_H */
