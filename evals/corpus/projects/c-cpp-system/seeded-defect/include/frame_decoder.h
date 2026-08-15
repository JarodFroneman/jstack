#ifndef JSTACK_FRAME_DECODER_H
#define JSTACK_FRAME_DECODER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool frame_decode_text(
    const uint8_t *frame,
    size_t frame_length,
    char *output,
    size_t output_capacity
);

#endif
