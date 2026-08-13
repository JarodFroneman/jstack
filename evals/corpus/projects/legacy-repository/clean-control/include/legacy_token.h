#ifndef JSTACK_LEGACY_TOKEN_H
#define JSTACK_LEGACY_TOKEN_H

#include <stddef.h>

int legacy_token_equal(
    const unsigned char *stored,
    size_t stored_length,
    const unsigned char *supplied,
    size_t supplied_length
);

#endif
