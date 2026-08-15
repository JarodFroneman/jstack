#include "frame_decoder.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_decodes_a_valid_frame(void) {
    const uint8_t frame[] = {0U, 5U, 'h', 'e', 'l', 'l', 'o'};
    char output[6];

    assert(frame_decode_text(frame, sizeof(frame), output, sizeof(output)));
    assert(strcmp(output, "hello") == 0);
}

static void test_rejects_a_truncated_payload(void) {
    const uint8_t frame[] = {0U, 4U, 'o', 'k'};
    char output[8] = "stable";

    assert(!frame_decode_text(frame, sizeof(frame), output, sizeof(output)));
    assert(strcmp(output, "stable") == 0);
}

static void test_accepts_an_empty_payload(void) {
    const uint8_t frame[] = {0U, 0U};
    char output[1] = {'x'};

    assert(frame_decode_text(frame, sizeof(frame), output, sizeof(output)));
    assert(output[0] == '\0');
}

int main(void) {
    test_decodes_a_valid_frame();
    test_rejects_a_truncated_payload();
    test_accepts_an_empty_payload();
    puts("3 public tests passed");
    return 0;
}
