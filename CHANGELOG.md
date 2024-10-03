## v1.12.0 (2024-10-03)

### New Features

- **esp-coredump**: add esp32c61 chip support

### Bug Fixes

- **python3.12**: replace distutils with shutil
- **gdb**: EspGDB descrutor Thread exceptions fix

## v1.11.0 (2024-04-12)

### New Features

- **esp-coredump**: add esp32c5 chip support
- make serial port arg optional

### Bug Fixes

- add cli option to pass partition table offset
- **coredump**: handle value errors when parsing TCB variable

### Performance Improvements

- **loader**: always use esptool to load coredump from flash

## v1.10.0 (2024-01-10)

### New Features

- **esp-coredump**: add esp32p4 chip support

## v1.9.0 (2023-12-06)

### New Features

- add auto detection for core file format

## v1.8.0 (2023-11-20)

### New Features

- **esp-coredump**: increase version to 1.8.0
- **coredump**: print isr context from elf file

## v1.7.0 (2023-08-07)

### New Features

- **esp-coredump**: increase version to 1.7.0
- **coredump**: parse panic_details from elf file

## v1.6.0 (2023-07-05)

### Bug Fixes

- **coredump-info**: esp32c2/esp32c6/esp32h2 corefile support

## v1.5.2 (2023-06-06)

### New Features

- **coredump-info**: retry reading thread info if not successful

## v1.5.1 (2023-05-22)

### Bug Fixes

- increase the version of the package

## v1.5.0 (2023-02-21)

### New Features

- add functionality to load ROM symbols automatically

### Bug Fixes

- fix isort error
- update pre-commit flake8 repo
