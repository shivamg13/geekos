#!/bin/bash
grep -A 1 "if(TEST_READ_FAULTS)" ../src/geekos/paging.c | tail -1 | sed 's/Print(\"\(.*\)\"/\1/g' | sed 's/\(.*\),.*/\1/g' > inp;
sed "s/#%x##/$(cat inp)/g" ../src/geekos/vfs-temp.c  > temp.cc
cp temp.cc ../src/geekos/vfs.c