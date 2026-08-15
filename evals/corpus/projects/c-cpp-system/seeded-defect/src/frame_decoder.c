#include "frame_decoder.h"

#include <string.h>

bool frame_decode_text(
    const uint8_t *frame,
    size_t frame_length,
    char *output,
    size_t output_capacity
) {
    size_t payload_length;

    if (frame == NULL || output == NULL || frame_length < 2U) {
        return false;
    }

    payload_length = ((size_t)frame[0] << 8U) | (size_t)frame[1];
    if (payload_length > frame_length - 2U || payload_length > output_capacity) {
        return false;
    }

    memcpy(output, frame + 2U, payload_length);
    output[payload_length] = '\0';
    return true;
}
