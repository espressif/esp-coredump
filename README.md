# esp-coredump

A Python-based utility that helps users to retrieve and analyse core dumps. This tool provides two commands for core dumps analysis:

- `info_corefile` - prints crashed task’s registers, callstack, list of available tasks in the system, memory regions and contents of memory stored in core dump (TCBs and stacks)

- `dbg_corefile` - creates core dump ELF file and runs GDB debug session with this file. User can examine memory, variables and tasks states manually. Note that since not all memory is saved in core dump only values of variables allocated on stack will be meaningful

## Installation

**esp-coredump** is a stand-alone utility integrated into ESP-IDF.

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
