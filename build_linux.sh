#!/usr/bin/env bash

set -e

cd user

make clean
make

python3 ../tools/verify_psp1000_safety.py \
    --source-root .. --user-elf zerovsh_upatcher.elf

bin2c zerovsh_upatcher.prx zerovsh_upatcher.h zerovsh_user_module
python3 ../tools/align_bin2c.py zerovsh_upatcher.h zerovsh_user_module

cp zerovsh_upatcher.h ../kernel
rm -f *.prx *.elf zerovsh_upatcher.h

cd ../kernel

make clean
make DEBUG=1

symbol_address="$(psp-nm -n zerovsh_patcher.elf | awk '
    $3 == "zerovsh_user_module" { address = $1; count++ }
    END { if (count != 1) exit 1; print address }
')"
if [[ ! "$symbol_address" =~ ^[[:xdigit:]]+$ ]]; then
    echo "error: invalid zerovsh_user_module symbol address: $symbol_address" >&2
    exit 1
fi
if (( (0x$symbol_address) % 64 != 0 )); then
    echo "error: zerovsh_user_module is not 64-byte aligned: 0x$symbol_address" >&2
    exit 1
fi
echo "verified zerovsh_user_module ELF address: 0x$symbol_address (64-byte aligned)"

cp zerovsh_patcher.prx ../bin
rm -f *.prx *.elf zerovsh_upatcher.h

cd ../
