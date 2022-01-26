# esp-coredump

A Python-based utility that helps users to retrieve and analyse core dumps. This tool provides two commands for core dumps analysis:

- `info_corefile` - prints crashed task’s registers, callstack, list of available tasks in the system, memory regions and contents of memory stored in core dump (TCBs and stacks)

- `dbg_corefile` - creates core dump ELF file and runs GDB debug session with this file. User can examine memory, variables and tasks states manually. Note that since not all memory is saved in core dump only values of variables allocated on stack will be meaningful

###### The tool is only compatible with Espressif chips and requires the installation of the ESP-IDF framework (please see the **Installation** section for further information).

## Installation

**esp-coredump** utility is offered as a part of **ESP-IDF** framework and should not be deployed as a standalone tool.

To install the **ESP-IDF** framework please visit the [documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html).

## Examples

`esp-coredump` can be used as a CLI tool as well as separate package

Build  `test_apps` for a target, flash and get a base64 text (`test_apps` folder)

```python
from esp_coredump import CoreDump

# Instantiate the coredump object
coredump = CoreDump(chip='esp32',core="./test/esp32/coredump.b64",core_format='b64', prog='./test_apps/build/test_core_dump.elf')
coredump.info_corefile()  #  print the info of the test app corefile
coredump.dbg_corefile()  #  run GDB debug session with provided ELF file
```

## Documentation

Visit the [documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/core_dump.html) or run `esp-coredump -h`.

## License

This document and the attached source code are released as Free Software under Apache Software License Version 2.0.
