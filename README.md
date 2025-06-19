# VMwhere - LLVM Obfuscation Engine

VMwhere is a flexible obfuscation engine built on the LLVM framework that protects intellectual property by applying various obfuscation and anti-reverse engineering techniques at compile-time and link-time. It provides comprehensive protection against both static and dynamic analysis without requiring any source code modifications.

All tests and demonstrations are performed on `test/main.c`, which contains a complete AES-128 encryption implementation (modified from tiny-AES-c). This provides a realistic cryptographic workload to evaluate the effectiveness of each obfuscation technique.

## Technical Report

**For comprehensive technical details, implementation specifics, and performance analysis, see the detailed report:**
- **[Technical Report (Markdown)](report/VMwhere_report.md)** - Complete documentation with architecture details
- **[Technical Report (PDF)](report/VMwhere_report.pdf)** - Same content with diagrams and visual examples

The report includes:
- Detailed threat model and objectives
- LLVM architecture explanation and implementation details
- Step-by-step implementation of each obfuscation technique
- Performance benchmarks and analysis on multiple systems
- Visual comparisons of obfuscated vs original code
- Anti-debugging mechanism deep-dive with syscall obfuscation
- Academic references and related work

## Key Features

- **String Obfuscation**: XOR encryption of strings at compile-time
- **Instruction Substitution**: Replaces simple operations with complex equivalents  
- **Control Flow Flattening**: Obfuscates control flow using switch-case constructs
- **Anti-Disassembly**: Injects crafted bytes to confuse disassemblers and decompilers
- **Runtime Anti-Debug**: Function wrapping and custom syscall obfuscation
- **No Source Modifications**: All transformations happen at IR/link level

## Project Structure

```
VMwhere/
├── src/
│   ├── passes/                    # LLVM obfuscation passes
│   │   ├── obfuscate_strings.cpp  # String encryption pass
│   │   ├── instruction_replace.cpp # Instruction substitution pass
│   │   ├── flatten.cpp            # Control flow flattening pass
│   │   └── anti-disassembly.cpp   # Anti-disassembly pass
│   ├── hooks/
│   │   └── start_main_hook.c      # Runtime anti-debug hooks
│   └── string_decrypt.c           # String decryption utilities
├── test/
│   └── main.c                     # Test program (AES-128 encryption implementation)
├── passes/                        # Compiled LLVM passes (.so files)
├── hooks/                         # Compiled hook objects (.o files)
├── build/                         # Final binaries
├── report/                        # Detailed technical report
│   ├── VMwhere_report.md          # Comprehensive documentation
│   └── VMwhere_report.pdf         # PDF version with diagrams
├── build.sh                       # Docker-based build script
├── bench.sh                       # Performance benchmarking
├── compare.sh                     # Output verification
├── runner.sh                      # Execute binaries
├── Makefile                       # Local build system
└── Dockerfile                     # Build environment
```

## Quick Start

### Method 1: Docker Build (Recommended)

The easiest way to build VMwhere is using the provided Docker setup:

```bash
# Ensure Docker is running
./build.sh
```

This will:
- Build a Docker container with all dependencies
- Compile all LLVM passes and hooks
- Generate both original and obfuscated binaries in `./build/`

**Output files:**
- `./build/original` - Unobfuscated binary
- `./build/safe_main` - Fully obfuscated binary

### Method 2: Local Build

If you have LLVM/Clang installed locally:

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install clang llvm llvm-dev build-essential

# Build everything
make all

# Or build specific components
make passes    # Build LLVM passes only
make hooks     # Build runtime hooks only  
make build     # Build final binaries
```

## Individual Pass Usage

Each obfuscation technique is implemented as a separate LLVM pass that can be used independently:

### String Obfuscation
```bash
# Build the pass
clang++ -fPIC -shared src/passes/obfuscate_strings.cpp -o passes/obfuscate_strings.so

# Apply to source
clang -fpass-plugin=./passes/obfuscate_strings.so main.c -o obfuscated_main
```

### Instruction Substitution  
```bash
# Build the pass
clang++ -fPIC -shared src/passes/instruction_replace.cpp -o passes/instruction_replace.so

# Apply to source (replaces additions with boolean operations)
clang -fpass-plugin=./passes/instruction_replace.so main.c -o obfuscated_main
```

### Control Flow Flattening
```bash
# Build the pass
clang++ -fPIC -shared src/passes/flatten.cpp -o passes/flatten.so

# Apply to source
clang -fpass-plugin=./passes/flatten.so main.c -o obfuscated_main
```

### Anti-Disassembly
```bash
# Build the pass
clang++ -fPIC -shared src/passes/anti-disassembly.cpp -o passes/anti-disassembly.so

# Apply to source
clang -fpass-plugin=./passes/anti-disassembly.so main.c -o obfuscated_main
```

### Combining Multiple Passes
```bash
# Apply all passes together
clang -static \
  -fpass-plugin=./passes/obfuscate_strings.so \
  -fpass-plugin=./passes/instruction_replace.so \
  -fpass-plugin=./passes/flatten.so \
  -fpass-plugin=./passes/anti-disassembly.so \
  main.c -o fully_obfuscated
```

### Runtime Anti-Debug (Function Wrapping)
```bash
# Compile with runtime hooks
clang -static main.c hooks/start_main_hook.o \
  -Wl,--wrap=printf -Wl,--wrap=main \
  -o anti_debug_main

# Strip symbols for additional protection
llvm-strip anti_debug_main
```

## Testing & Verification

### Functional Testing
Verify that obfuscated binaries produce identical output:
```bash
./compare.sh
```

### Performance Benchmarking
Measure performance impact of obfuscation:
```bash
./bench.sh
```

This uses `hyperfine` to benchmark 1000 random inputs on the AES implementation and reports:
- Average execution time for original vs obfuscated AES
- Slowdown factor introduced by obfuscation

### Manual Testing
```bash
# Run original AES binary
./build/original "test input"

# Run obfuscated AES binary  
./build/safe_main "test input"

# Both will encrypt the input and display ciphertext + debug info
```

## Build System Details

### Makefile Targets
- `make all` - Build passes, hooks, and binaries
- `make passes` - Compile all LLVM passes to `.so` files
- `make hooks` - Compile runtime hooks to `.o` files  
- `make build` - Link final binaries with all obfuscations
- `make clean` - Remove all build artifacts

### Docker Multi-Stage Build
The Dockerfile uses a multi-stage build for efficiency:
1. **Builder stage**: Debian with full toolchain for compilation
2. **Runtime stage**: Minimal Alpine with only build artifacts

## Obfuscation Techniques Explained

### 1. String Obfuscation
- **Mechanism**: XOR encryption with random key at compile-time
- **Effect**: Strings invisible to static analysis tools
- **Implementation**: LLVM IR pass extracts globals, encrypts, injects decryption calls

### 2. Instruction Substitution  
- **Mechanism**: Replaces `A + B` with `(A ^ B) + ((A & B) << 1)`
- **Effect**: Obscures simple arithmetic operations
- **Scope**: All 32-bit integer additions

### 3. Control Flow Flattening
- **Mechanism**: Wraps all basic blocks in switch-case with dispatch variable
- **Effect**: Destroys natural control flow structure
- **Result**: Makes reverse engineering significantly harder

### 4. Anti-Disassembly
- **Mechanism**: Injects crafted x86 bytes that exploit disassembler weaknesses
- **Effect**: Causes disassemblers to produce incorrect assembly listings
- **Randomization**: Each injection is slightly randomized to prevent patching

### 5. Runtime Anti-Debug
- **Function Wrapping**: Intercepts `main()` and `printf()` calls
- **Custom Syscalls**: Uses non-standard syscall numbers and argument orders
- **Process Monitoring**: Parent process uses ptrace to translate syscalls
- **Anti-Attach**: Prevents external debuggers from attaching

## Requirements

### For Docker Build
- Docker
- Bash

### for Local Build  
- Clang/LLVM (version 14+)
- Build essentials (make, gcc)
- Linux x86_64

### For Testing
- `hyperfine` (auto-installed by `bench.sh`)
- `jq` (for benchmark result parsing)
- `bc` (for calculations)

## Additional Resources

For more information about building and testing, see the shell scripts in the root directory:
- `build.sh` - Automated Docker-based build
- `bench.sh` - Performance benchmarking with hyperfine
- `compare.sh` - Functional correctness verification

## Workflow Example

```bash
# 1. Build the engine
./build.sh

# 2. Verify functionality  
./compare.sh

# 3. Benchmark performance
./bench.sh

# 4. Test AES binaries
echo "Testing original AES:"
./build/original "hello world"

echo "Testing obfuscated AES:"  
./build/safe_main "hello world"

# 5. Try debugging (will fail/behave differently)
gdb ./build/safe_main
```

## Performance Impact

Based on AES encryption benchmarks (AMD Ryzen 7 7735HS, 16GB RAM):
- **Slowdown Factor**: ~1.2x typical for AES operations
- **Binary Size**: Moderate increase due to injected obfuscation bytes
- **Memory Usage**: Minimal additional overhead

## Security Considerations

VMwhere provides protection against:
- Static analysis (strings, control flow, instructions)
- Disassembly and decompilation  
- Dynamic debugging with GDB/similar tools
- Syscall tracing with strace

**Note**: Like all obfuscation, this raises the bar for reverse engineering but doesn't provide absolute security. Determined attackers with sufficient time and expertise may still analyze obfuscated binaries.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your obfuscation technique as an LLVM pass
4. Add tests and documentation
5. Submit a pull request

## License

This project is available for educational and research purposes. See the detailed report for academic references and implementation details.
