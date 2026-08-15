#include "decimal_counter.h"

#include <limits.h>
#include <stddef.h>

bool parse_decimal_counter(const char *text, uint32_t *value) {
    uint32_t parsed = 0U;
    size_t index = 0U;

    if (text == NULL || value == NULL || text[0] == '\0') {
        return false;
    }
    if (text[0] == '0' && text[1] != '\0') {
        return false;
    }

    while (text[index] != '\0') {
        uint32_t digit;
        if (text[index] < '0' || text[index] > '9') {
            return false;
        }
        digit = (uint32_t)(text[index] - '0');
        if (parsed > (UINT32_MAX - digit) / 10U) {
            return false;
        }
        parsed = parsed * 10U + digit;
        index += 1U;
    }

    *value = parsed;
    return true;
}
