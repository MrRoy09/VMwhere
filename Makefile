SH    := bash
CC    := clang
CXX   := clang++
CFLAGS   := -fPIC -shared
CXXFLAGS := -fPIC -shared -O2

SRC_DIR   := src
PASSES_DIR:= passes
HOOKS_DIR := hooks

PASS_SRCS := $(wildcard $(SRC_DIR)/passes/*.cpp)
PASS_OBJS := $(patsubst $(SRC_DIR)/passes/%.cpp,$(PASSES_DIR)/%.so,$(PASS_SRCS))

HOOK_SRCS := $(wildcard $(SRC_DIR)/hooks/*.c)
HOOK_OBJS := $(patsubst $(SRC_DIR)/hooks/%.c,$(HOOKS_DIR)/%.o,$(HOOK_SRCS))

MAIN_DIR  := test
BUILD_DIR := build

all: passes hooks build

passes: $(PASS_OBJS)

$(PASSES_DIR)/%.so: $(SRC_DIR)/passes/%.cpp
	@mkdir -p $(PASSES_DIR)
	$(CXX) $(CXXFLAGS) $< -o $@

hooks: $(HOOK_OBJS)

$(HOOKS_DIR)/%.o: $(SRC_DIR)/hooks/%.c | passes
	@mkdir -p $(HOOKS_DIR)
	$(CC) $(CFLAGS) -static -c $(addprefix -fpass-plugin=,$(PASS_OBJS)) $< -o $@

build: hooks
	@mkdir -p $(BUILD_DIR)
	$(CC) -c $(addprefix -fpass-plugin=,$(PASS_OBJS)) $(SRC_DIR)/string_decrypt.c -o $(MAIN_DIR)/string_decrypt.o
	$(CC) -c $(addprefix -fpass-plugin=,$(PASS_OBJS)) $(MAIN_DIR)/main.c -o $(MAIN_DIR)/main.o
	$(CC) -static $(MAIN_DIR)/main.o $(HOOKS_DIR)/start_main_hook.o $(MAIN_DIR)/string_decrypt.o -Wl,--wrap=printf -Wl,--wrap=main -o $(BUILD_DIR)/safe_main
	llvm-strip $(BUILD_DIR)/safe_main
	$(CC) -static $(MAIN_DIR)/main.c -o $(BUILD_DIR)/original

clean:
	rm -f $(PASSES_DIR)/*.so
	rm -f $(HOOKS_DIR)/*.o $(HOOKS_DIR)/start_main_hook.o
	rm -f $(MAIN_DIR)/main.o $(HOOKS_DIR)/start_main_hook.o $(BUILD_DIR)/out
	rm -f $(BUILD_DIR)/safe_main $(BUILD_DIR)/original

.PHONY: all passes hooks build clean
