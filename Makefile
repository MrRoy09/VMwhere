SH	:= bash
CXX := clang++
CXXFLAGS := -fPIC -shared `llvm-config --cxxflags --ldflags --system-libs --libs core passes`
SRC_DIR := src
OUT_DIR := passes

TARGETS := $(addprefix $(OUT_DIR)/, strings.so anti-disasm.so flatten.so instruction_replace.so)
SOURCES := $(addprefix $(SRC_DIR)/, obfuscate_strings.cpp anti-disassembly.cpp flatten.cpp instruction_replace.cpp)

passes: $(TARGETS)

$(OUT_DIR)/strings.so: $(SRC_DIR)/obfuscate_strings.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

$(OUT_DIR)/anti-disasm.so: $(SRC_DIR)/anti-disassembly.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

$(OUT_DIR)/flatten.so: $(SRC_DIR)/flatten.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

$(OUT_DIR)/instruction_replace.so: $(SRC_DIR)/instruction_replace.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f $(OUT_DIR)/*.so
