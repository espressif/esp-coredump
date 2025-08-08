# esp-coredump

A Python-based utility that helps users to retrieve and analyse core dumps. This tool provides two commands for core dumps analysis:

- `info_corefile` - prints crashed task’s registers, callstack, list of available tasks in the system, memory regions and contents of memory stored in core dump (TCBs and stacks)

- `dbg_corefile` - creates core dump ELF file and runs GDB debug session with this file. User can examine memory, variables and tasks states manually. Note that since not all memory is saved in core dump only values of variables allocated on stack will be meaningful

## Installation

**esp-coredump** is a standalone utility integrated into ESP-IDF. It is recommended to run `esp-coredump` from within ESP-IDF environment due to the ease of setup.

To install the **ESP-IDF** framework please visit the [documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/index.html).

### Standalone Installation (without ESP-IDF)

If you're attempting to run `esp-coredump` outside of the ESP-IDF environment, you'll need to install `esp-gdb`. The most recent version can be downloaded from the [GitHub releases](https://github.com/espressif/binutils-gdb/releases) page. To determine the appropriate version for your environment, refer to the [ESP-IDF documentation](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-guides/tools/idf-tools.html#xtensa-esp-elf-gdb).
Note that toolchain versions may vary between ESP-IDF versions. To get the correct version for your needs, select your version of ESP-IDF in the top left corner.
Ensure you download the correct version that matches the architecture of your ESP32. After downloading the toolchain, verify that it's accessible in your system's PATH.

## Examples

`esp-coredump` can be used as a CLI tool as well as a separate package. Before executing any examples, ensure that all requirements outlined in the [Installation](#installation) section have been met. If you decide to use ESP-IDF, all commands should be run from within the ESP-IDF environment.

Build  `test_apps` for a target, flash and get a base64 text (`test_apps` folder)

```python
from esp_coredump import CoreDump

# Instantiate the coredump object
coredump = CoreDump(chip='esp32', core="./tests/esp32/coredump.b64", print_mem=True, core_format='b64', prog='./test_apps/build/test_core_dump.elf')
coredump.info_corefile()  #  print the info of the test app corefile
coredump.dbg_corefile()  #  run GDB debug session with provided ELF file
```

## Documentation

Visit the [documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/core_dump.html) or run `esp-coredump -h`.

## Contributing

### Code Style & Static Analysis

Please follow these coding standards when writing code for ``esp-coredump``:

#### Pre-commit checks

[pre-commit](https://pre-commit.com/) is a framework for managing pre-commit hooks. These hooks help to identify simple issues before committing code for review.

To use the tool, first install ``pre-commit``. Then enable the ``pre-commit`` and ``commit-msg`` git hooks:

```sh
python -m pip install pre-commit
pre-commit install -t pre-commit -t commit-msg
```

On the first commit ``pre-commit`` will install the hooks, subsequent checks will be significantly faster. If an error is found an appropriate error message will be displayed.


#### Conventional Commits

``esp-coredump`` complies with the [Conventional Commits standard](https://www.conventionalcommits.org/en/v1.0.0/#specification). Every commit message is checked with [Conventional Precommit Linter](https://github.com/espressif/conventional-precommit-linter), ensuring it adheres to the standard.


## License

This document and the attached source code are released as Free Software under Apache Software License Version 2.0.
