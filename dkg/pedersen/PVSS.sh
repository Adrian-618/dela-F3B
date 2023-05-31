#!/bin/sh
# for n in 8 16 32 64 128
for n in 128 128 128 128
do
    LLVL=warn go test -run Test_PVSS_records -timeout 0 -args -n=$n
    sleep 10
done