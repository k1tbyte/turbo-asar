/**
 * @file pickle.c
 *
 * https://github.com/electron/asar/blob/main/src/pickle.ts
 *
 * Created by kitbyte on 08.11.2025.
 */

#include "pickle.h"
#include <stdlib.h>
#include <string.h>

/* Initial buffer capacity for writer */
#define INITIAL_CAPACITY 64

/* Align value up to PICKLE_ALIGN boundary */
static inline size_t align_up(size_t value)
{
    return (value + (PICKLE_ALIGN - 1)) & ~(PICKLE_ALIGN - 1);
}

/* ----- Reader Implementation ----- */

bool pickle_reader_init(pickle_reader_t *reader, const uint8_t *data, size_t size)
{
    if (!reader || !data || size < 4) {
        return false;
    }

    reader->data = data;
    reader->data_size = size;
    reader->header_size = 4;  /* Standard pickle header is 4 bytes */

    /* Read payload size from header (little-endian) */
    reader->payload_size = (uint32_t)data[0] |
                          ((uint32_t)data[1] << 8) |
                          ((uint32_t)data[2] << 16) |
                          ((uint32_t)data[3] << 24);

    /* Validate payload size */
    if (reader->header_size + reader->payload_size > size) {
        return false;
    }

    reader->read_offset = 0;
    return true;
}

bool pickle_read_uint32(pickle_reader_t *reader, uint32_t *value)
{
    if (!reader || !value) {
        return false;
    }

    /* Check bounds */
    if (reader->read_offset + 4 > reader->payload_size) {
        return false;
    }

    const uint8_t *ptr = reader->data + reader->header_size + reader->read_offset;
    *value = (uint32_t)ptr[0] |
             ((uint32_t)ptr[1] << 8) |
             ((uint32_t)ptr[2] << 16) |
             ((uint32_t)ptr[3] << 24);

    /* Advance with alignment */
    reader->read_offset = align_up(reader->read_offset + 4);
    return true;
}

bool pickle_read_int32(pickle_reader_t *reader, int32_t *value)
{
    uint32_t uvalue;
    if (!pickle_read_uint32(reader, &uvalue)) {
        return false;
    }
    *value = (int32_t)uvalue;
    return true;
}

bool pickle_read_string(pickle_reader_t *reader, const char **str, size_t *len)
{
    if (!reader || !str || !len) {
        return false;
    }

    int32_t length;
    if (!pickle_read_int32(reader, &length) || length < 0) {
        return false;
    }

    *len = (size_t)length;

    /* Check bounds for string data */
    if (reader->read_offset + *len > reader->payload_size) {
        return false;
    }

    *str = (const char *)(reader->data + reader->header_size + reader->read_offset);

    /* Advance with alignment */
    reader->read_offset = align_up(reader->read_offset + *len);
    return true;
}

bool pickle_read_string_copy(pickle_reader_t *reader, char **str)
{
    const char *ptr;
    size_t len;

    if (!pickle_read_string(reader, &ptr, &len)) {
        return false;
    }

    *str = (char *)malloc(len + 1);
    if (!*str) {
        return false;
    }

    memcpy(*str, ptr, len);
    (*str)[len] = '\0';
    return true;
}

/* ----- Writer Implementation ----- */

static bool pickle_writer_ensure_capacity(pickle_writer_t *writer, size_t needed)
{
    size_t total_needed = writer->header_size + writer->write_offset + needed;
    
    if (total_needed <= writer->capacity) {
        return true;
    }

    size_t new_capacity = writer->capacity * 2;
    while (new_capacity < total_needed) {
        new_capacity *= 2;
    }

    uint8_t *new_data = (uint8_t *)realloc(writer->data, new_capacity);
    if (!new_data) {
        return false;
    }

    writer->data = new_data;
    writer->capacity = new_capacity;
    return true;
}

static void pickle_writer_update_header(pickle_writer_t *writer)
{
    /* Write payload size to header (little-endian) */
    uint32_t payload_size = (uint32_t)writer->write_offset;
    writer->data[0] = (uint8_t)(payload_size);
    writer->data[1] = (uint8_t)(payload_size >> 8);
    writer->data[2] = (uint8_t)(payload_size >> 16);
    writer->data[3] = (uint8_t)(payload_size >> 24);
}

bool pickle_writer_init(pickle_writer_t *writer)
{
    if (!writer) {
        return false;
    }

    writer->data = (uint8_t *)malloc(INITIAL_CAPACITY);
    if (!writer->data) {
        return false;
    }

    writer->capacity = INITIAL_CAPACITY;
    writer->header_size = 4;
    writer->write_offset = 0;

    /* Zero out header */
    memset(writer->data, 0, writer->header_size);
    return true;
}

void pickle_writer_free(pickle_writer_t *writer)
{
    if (writer && writer->data) {
        free(writer->data);
        writer->data = NULL;
        writer->capacity = 0;
    }
}

bool pickle_write_uint32(pickle_writer_t *writer, uint32_t value)
{
    if (!writer) {
        return false;
    }

    size_t aligned_size = align_up(4);
    if (!pickle_writer_ensure_capacity(writer, aligned_size)) {
        return false;
    }

    uint8_t *ptr = writer->data + writer->header_size + writer->write_offset;
    ptr[0] = (uint8_t)(value);
    ptr[1] = (uint8_t)(value >> 8);
    ptr[2] = (uint8_t)(value >> 16);
    ptr[3] = (uint8_t)(value >> 24);

    /* Zero padding bytes */
    if (aligned_size > 4) {
        memset(ptr + 4, 0, aligned_size - 4);
    }

    writer->write_offset += aligned_size;
    pickle_writer_update_header(writer);
    return true;
}

bool pickle_write_int32(pickle_writer_t *writer, int32_t value)
{
    return pickle_write_uint32(writer, (uint32_t)value);
}

bool pickle_write_string(pickle_writer_t *writer, const char *str, size_t len)
{
    if (!writer || !str) {
        return false;
    }

    if (!pickle_write_int32(writer, (int32_t)len)) {
        return false;
    }

    size_t aligned_size = align_up(len);
    if (!pickle_writer_ensure_capacity(writer, aligned_size)) {
        return false;
    }

    uint8_t *ptr = writer->data + writer->header_size + writer->write_offset;
    memcpy(ptr, str, len);

    /* Zero padding bytes */
    if (aligned_size > len) {
        memset(ptr + len, 0, aligned_size - len);
    }

    writer->write_offset += aligned_size;
    pickle_writer_update_header(writer);
    return true;
}

const uint8_t* pickle_writer_data(pickle_writer_t *writer, size_t *size)
{
    if (!writer || !size) {
        return NULL;
    }

    *size = writer->header_size + writer->write_offset;
    return writer->data;
}

uint8_t* pickle_writer_copy(pickle_writer_t *writer, size_t *size)
{
    if (!writer || !size) {
        return NULL;
    }

    *size = writer->header_size + writer->write_offset;
    uint8_t *copy = (uint8_t *)malloc(*size);
    if (!copy) {
        return NULL;
    }

    memcpy(copy, writer->data, *size);
    return copy;
}
