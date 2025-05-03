#!/bin/bash

clang -c src/start_main_hook.c -O0
clang -static main.o start_main_hook.o -Wl,--wrap=main -Wl,--wrap=printf -o program