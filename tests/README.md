| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C6 | ESP32-H2 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | -------- | -------- |

# ESP Core Dump Tests

Current directory includes the tests and tests data that is supposed to be used in testing of `esp-coredump` package

This directory includes tests data that is not intended to be used in testing apps that doesn't have the loading of rom-elf-files capabilities (`esp32` and `esp32c3` directories) and tests data for the apps that have this feature (`./rom_tests/esp32` and `./rom_tests/esp32c3` directories).

Since all the current applications (that are built within ESP-IDF version >= 5.1) have the ability to load rom-elf-files, it is not required to update tests data in the directories named `esp32` and `esp32c3`. Instead, update the files inside `./rom_tests/esp32` and `./rom_tests/esp32c3` directories.

## Update coredump.b64 test data

To update `./rom_tests/<target>/coredump.b64`  (for ESP-IDF version >= 5.1)  and `./<target>/coredump.b64` (for ESP-IDF version < 5.1) build `test_apps` for a target, flash and get a base64 text from `idf.py monitor`

For more information how to build the test apps see _./test_apps/README.md_.

## ELF test binaries

The ELF test binaries are placed in _./test_apps/built_apps folder_


## Update expected_output test data

To update `./rom_tests/<target>/expected_output` run

```
TARGET=esp32
espcoredump.py --chip $TARGET info_corefile -c ./rom_tests/$TARGET/coredump.b64 -t b64 -m $IDF_COREDEMP_ELF_DIR/rom_tests/$TARGET.elf > ./rom_tests/$TARGET/expected_output
```

To update `./<target>/expected_output` (for ESP-IDF version < 5.1) run

```
TARGET=esp32
espcoredump.py --chip $TARGET info_corefile -c ./$TARGET/coredump.b64 -t b64 -m $IDF_COREDEMP_ELF_DIR/$TARGET.elf > ./$TARGET/expected_output
```

Do the same for riscv target esp32c3.
