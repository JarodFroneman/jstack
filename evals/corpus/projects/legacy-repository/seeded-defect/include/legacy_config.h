#ifndef JSTACK_LEGACY_CONFIG_H
#define JSTACK_LEGACY_CONFIG_H

#include <stddef.h>

int legacy_config_lookup(
    const char *contents,
    const char *key,
    char *output,
    size_t output_capacity
);

#endif
