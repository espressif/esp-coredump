| Supported Targets | ESP32 | ESP32-C2 | ESP32-C3 | ESP32-C6 | ESP32-H2 | ESP32-S2 | ESP32-S3 |
| ----------------- | ----- | -------- | -------- | -------- | -------- | -------- | -------- |

# ESP-IDF Coredump Test ELFs

This directory includes the test elf files for the idf coredump output test (`built_apps` folder).

This directory includes both apps that are not intended to test the loading of rom-elf-files capabilities automatically of the coredump package (files that are placed in the `built_apps` directory) and apps to test this feature (`built_apps/rom_tests` directory).

## Build Process

To build the apps use the following commands:

```shell
$ export IDF_PATH=<your_idf_path>
$ loc=$(pwd)
$ bash $IDF_PATH/install.sh
$ . $IDF_PATH/export.sh
$ bash ./build_espcoredump.sh $loc
```
