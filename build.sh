#!/bin/bash

clang -c src/start_main_hook.c -O0 -gdwarf
clang -static main.o start_main_hook.o -Wl,--wrap=main -Wl,--wrap=printf -Wl,--wrap=__libc_start_main -o program -gdwarf