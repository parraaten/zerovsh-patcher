#!/usr/bin/env bash

set -e

cd user

make clean
make

bin2c zerovsh_upatcher.prx zerovsh_upatcher.h zerovsh_user_module

cp zerovsh_upatcher.h ../kernel
rm -f *.prx *.elf zerovsh_upatcher.h

cd ../kernel

make clean
make DEBUG=1

cp zerovsh_patcher.prx ../bin
rm -f *.prx *.elf zerovsh_upatcher.h

cd ../
