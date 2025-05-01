# Apply all obfuscation passes during compilation
clang -c -fpass-plugin=./strings.so -fpass-plugin=./anti-disasm.so -fpass-plugin=./flatten.so -fpass-plugin=./instruction_replace.so ../test/main.c -o ../test/main.o
clang -c -fpass-plugin=./strings.so -fpass-plugin=./anti-disasm.so -fpass-plugin=./flatten.so -fpass-plugin=./instruction_replace.so ../src/start_main_hook.c -o ../src/start_main_hook.o

# Then link
clang -static ../test/main.o ../src/start_main_hook.o ../test/string_decrypt.o -Wl,--wrap=__libc_start_main -o ../test/my_program