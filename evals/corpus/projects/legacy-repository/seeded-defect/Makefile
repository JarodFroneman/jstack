CC ?= cc
CFLAGS ?= -O2
CFLAGS += -std=c89 -Wall -Wextra -Wpedantic -Werror

BUILD_DIR := build
SYSTEM_NAME := $(shell uname -s)

ifeq ($(SYSTEM_NAME),Darwin)
LIBRARY := $(BUILD_DIR)/liblegacy_config.dylib
SHARED_FLAGS := -dynamiclib
else
LIBRARY := $(BUILD_DIR)/liblegacy_config.so
SHARED_FLAGS := -shared -fPIC
endif

.PHONY: all test

all: $(LIBRARY)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(LIBRARY): src/legacy_config.c include/legacy_config.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -I include src/legacy_config.c -o $(LIBRARY)

test: $(LIBRARY)
	JSTACK_LEGACY_LIBRARY="$(abspath $(LIBRARY))" PYTHONDONTWRITEBYTECODE=1 python3 tests/test_legacy_config.py
