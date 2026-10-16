| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C5 | ESP32-C61 | ESP32-C6 | ESP32-H2 | ESP32-H21 | ESP32-H4 | ESP32-S2 | ESP32-S3 | ESP32-P4 | ESP32-S31 |
| ----------------- | ----- | -------- | -------- | -------- | --------- | -------- | -------- | --------- | -------- | -------- | -------- | -------- | --------- |

# ESP Core Dump Tests

Current directory includes the tests and tests data that is supposed to be used in testing of `esp-coredump` package

Files created with `_bin` suffix were build with `CONFIG_ESP_COREDUMP_DATA_FORMAT_BIN=y` instead of the default ELF format.

## Update `coredump.b64` Test Data

To update `./<target>/coredump.b64` build `test_apps` for a target, flash and get a base64 text from `idf.py monitor`

For more information how to build the test apps see _./test_apps/README.md_.

## ELF Test Binaries

The ELF test binaries are placed in _./test_apps/$chip folder_

## Update `expected_output` Test Data

To update `./<target>/expected_output` run

```sh
TARGET=esp32
espcoredump.py --chip $TARGET info_corefile -c ./$TARGET/coredump.b64 -t b64 -m ./test_apps/build/test_core_dump.elf > ./$TARGET/expected_output
```

Do the same for the other supported targets. Do not forget to remove the first line with `espcoredump.py vX.Y.Z`.

## Update `expected_output_print_vars` Test Data

`./esp32s31/expected_output_print_vars` tests `--print-all-vars` and `--print-var`. Its files have the `_print_vars` suffix and were built with `sdkconfig.print_vars`, which adds variables tagged with `COREDUMP_*_ATTR` to the test app:

```sh
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.print_vars" set-target esp32s31 build
```

To update the expected output run

```sh
TARGET=esp32s31
espcoredump.py --chip $TARGET info_corefile -c ./$TARGET/coredump_print_vars.b64 -t b64 --print-all-vars --print-var "/x \$pc" --print-var "'tasks.c'::xTickCount" --print-var no_such_symbol --print-var "esp_isr_names[2]" --print-var g_batt.mv ./test_apps/built_apps/${TARGET}_print_vars.elf > ./$TARGET/expected_output_print_vars
```

Remove the first line with `espcoredump.py vX.Y.Z`.
