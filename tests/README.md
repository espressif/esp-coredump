| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C5 | ESP32-C61 | ESP32-C6 | ESP32-H2 | ESP32-S2 | ESP32-S3 | ESP32-P4 |
| ----------------- | ----- | -------- | -------- | -------- | --------- | -------- | -------- | -------- | -------- | -------- |

# ESP Core Dump Tests

Current directory includes the tests and tests data that is supposed to be used in testing of `esp-coredump` package

## Update coredump.b64 test data

To update `./<target>/coredump.b64` build `test_apps` for a target, flash and get a base64 text from `idf.py monitor`

For more information how to build the test apps see _./test_apps/README.md_.

## ELF test binaries

The ELF test binaries are placed in _./test_apps/$chip folder_


## Update expected_output test data

To update `./<target>/expected_output` run

```
TARGET=esp32
espcoredump.py --chip $TARGET info_corefile -c ./$TARGET/coredump.b64 -t b64 -m ./test_apps/build/test_core_dump.elf > ./$TARGET/expected_output
```

Do the same for the other supported targets.
