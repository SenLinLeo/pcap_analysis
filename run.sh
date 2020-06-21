#!/bin/bash 
export LD_LIBRARY_PATH=$(pwd)
gcc test_main.c -lfilter-test -lpcap -L.

