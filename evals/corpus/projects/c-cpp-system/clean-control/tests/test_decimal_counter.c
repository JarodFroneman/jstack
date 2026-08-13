#include "decimal_counter.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void) {
    uint32_t value = 17U;

    assert(parse_decimal_counter("0", &value));
    assert(value == 0U);
    assert(parse_decimal_counter("4294967295", &value));
    assert(value == UINT32_MAX);

    value = 17U;
    assert(!parse_decimal_counter("4294967296", &value));
    assert(value == 17U);
    assert(!parse_decimal_counter("-1", &value));
    assert(!parse_decimal_counter("12items", &value));
    assert(!parse_decimal_counter("00", &value));
    assert(!parse_decimal_counter("", &value));

    puts("9 public assertions passed");
    return 0;
}
