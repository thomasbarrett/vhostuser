CC=clang
CFLAGS = -std=c11 -Wall -pedantic -Iinclude -Wall -O3 -Wno-address-of-packed-member
SRC_FILES = $(wildcard src/*.c)  $(wildcard src/*/*.c)
FILES = $(basename $(SRC_FILES:src/%=%))
OBJ_FILES = $(addprefix obj/,$(FILES:=.o))
TEST_FILES = $(addprefix bin/,$(basename $(wildcard tests/*.c) $(wildcard tests/*/*.c)))
VERSION = v0.1.0

.PHONY: all
all: bin/example $(TEST_FILES)

.PHONY: clean
clean:
	@rm -rf obj
	@rm -rf bin

.PHONY: build
build: $(TEST_FILES) $(OBJ_FILES)

obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	@$(CC) -c $(CFLAGS) $^ -o $@

bin/tests/%: tests/%.c
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -I. -fprofile-instr-generate -fcoverage-mapping $$(cat $^ | grep '// CFLAGS:' |  cut -d':' -f2-) $^ -o $@

bin/example: main/example.c $(OBJ_FILES)
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $^ -o $@ -laio

# suppress error for missing test file
bin/tests/%:
	@:

.PHONY: object-files
object-files:
	@echo $(OBJ_FILES)

.PHONY: test
test: $(TEST_FILES)
	tests/run.sh $(TEST_FILES)

.PHONY: version
version:
	@echo ${VERSION}

.PHONY: list-deps
list-deps:
	@:

.PHONY: install-deps
install-deps:
	@:

.PHONY: build-deps
build-deps:
	@:

.PHONY: lint
lint:
	@for file in $(SRC_FILES); do \
		clang-tidy $$file --checks=clang-analyzer-*,performance-* -- $(CFLAGS); \
	done
