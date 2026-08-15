#include "legacy_token.h"

int legacy_token_equal(
    const unsigned char *stored,
    size_t stored_length,
    const unsigned char *supplied,
    size_t supplied_length
) {
    size_t index;
    unsigned int difference = 0U;

    if (stored == NULL || supplied == NULL || stored_length == 0U ||
        stored_length != supplied_length) {
        return 0;
    }

    for (index = 0U; index < stored_length; index += 1U) {
        difference |= (unsigned int)(stored[index] ^ supplied[index]);
    }

    return difference == 0U ? 1 : 0;
}
