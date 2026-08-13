#include "legacy_config.h"

#include <string.h>

int legacy_config_lookup(
    const char *contents,
    const char *key,
    char *output,
    size_t output_capacity
) {
    const char *line;
    size_t key_length;

    if (contents == NULL || key == NULL || output == NULL || output_capacity == 0U) {
        return 0;
    }

    key_length = strlen(key);
    if (key_length == 0U) {
        return 0;
    }

    line = contents;
    while (*line != '\0') {
        const char *line_end;
        const char *equals;
        size_t line_length;

        line_end = strchr(line, '\n');
        if (line_end == NULL) {
            line_end = line + strlen(line);
        }
        line_length = (size_t)(line_end - line);

        if (line_length > key_length && line[0] != '#' &&
            strncmp(line, key, key_length) == 0) {
            size_t value_length;
            equals = (const char *)memchr(line, '=', line_length);
            if (equals != NULL) {
                value_length = (size_t)(line_end - equals - 1);
                if (value_length >= output_capacity) {
                    return 0;
                }
                memcpy(output, equals + 1, value_length);
                output[value_length] = '\0';
                return 1;
            }
        }

        line = *line_end == '\n' ? line_end + 1 : line_end;
    }

    return 0;
}
