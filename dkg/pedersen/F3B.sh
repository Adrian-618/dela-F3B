#!/bin/sh
for n in 8 16 32 64 128
do
    LLVL=warn go test -run Test_F3B_records -timeout 0 -args -n=$n
    sleep 10
done