#!/bin/bash

x86_64-w64-mingw32-gcc -w -shared injectedfunc.c -o ./build/injectedfunc.dll -D_WIN32_WINNT=0x0602 -lkernel32 -lversion
