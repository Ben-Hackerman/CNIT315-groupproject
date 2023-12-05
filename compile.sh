#!/bin/bash

x86_64-w64-mingw32-gcc -masm=intel -lkernel32 -luser32 -mconsole -shared injectedfunc.c -o ./build/injectedfunc.dll