#!/bin/bash

gcc test.c -L ../src -lreverse -o test
./test
