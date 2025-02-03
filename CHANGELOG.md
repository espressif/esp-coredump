<a href="https://www.espressif.com">
    <img src="https://www.espressif.com/sites/all/themes/espressif/logo-black.svg" align="right" height="20" />
</a>

# CHANGELOG

> All notable changes to this project are documented in this file.
> This list is not exhaustive - only important changes, fixes, and new features in the code are reflected here.

<div align="center">
    <a href="https://keepachangelog.com/en/1.1.0/">
        <img alt="Static Badge" src="https://img.shields.io/badge/Keep%20a%20Changelog-v1.1.0-salmon?logo=keepachangelog&logoColor=black&labelColor=white&link=https%3A%2F%2Fkeepachangelog.com%2Fen%2F1.1.0%2F">
    </a>
    <a href="https://www.conventionalcommits.org/en/v1.0.0/">
        <img alt="Static Badge" src="https://img.shields.io/badge/Conventional%20Commits-v1.0.0-pink?logo=conventionalcommits&logoColor=black&labelColor=white&link=https%3A%2F%2Fwww.conventionalcommits.org%2Fen%2Fv1.0.0%2F">
    </a>
    <a href="https://semver.org/spec/v2.0.0.html">
        <img alt="Static Badge" src="https://img.shields.io/badge/Semantic%20Versioning-v2.0.0-grey?logo=semanticrelease&logoColor=black&labelColor=white&link=https%3A%2F%2Fsemver.org%2Fspec%2Fv2.0.0.html">
    </a>
</div>
<hr>

## v1.13.0 (2025-02-03)

### ✨ New Features

- add support for new roms.json location *(Peter Dragun - 90a1a68)*

### 🐛 Bug Fixes

- **cli**: provide correct error messages and rework the script structure *(Peter Dragun - f15a82c)*
- Use Posix paths on Windows for loading symbols from file *(Roland Dobai - 4b7d3d8)*
- Fix empty env variable for ROM ELF directory *(Peter Dragun - 1c0295b)*
- close pipes in gdb subprocess *(Peter Dragun - 51fdc71)*


## v1.12.0 (2024-10-03)

### ✨ New Features

- **esp-coredump**: add esp32c61 chip support *(Erhan Kurubas - 7b75c8a)*

### 🐛 Bug Fixes

- **python3.12**: replace distutils with shutil *(Guilhem Saurel - d45c2e7)*
- **gdb**: EspGDB descrutor Thread exceptions fix *(Jakub Kocka - 50692f5)*

---

## v1.11.0 (2024-04-12)

### ✨ New Features

- **esp-coredump**: add esp32c5 chip support *(Erhan Kurubas - e5b6f5a)*
- make serial port arg optional *(Erhan Kurubas - 10c5ea9)*

### 🐛 Bug Fixes

- **coredump**: handle value errors when parsing TCB variable *(Erhan Kurubas - 683d00f)*
- add cli option to pass partition table offset *(Peter Dragun - ac7659d)*

### 📖 Documentation

- add instructions for standalone installation *(Peter Dragun - ce7a387)*

---

## v1.10.0 (2024-01-10)

### ✨ New Features

- **esp-coredump**: add esp32p4 chip support *(Erhan Kurubas - 890d68a)*

---

## v1.9.0 (2023-12-06)

### ✨ New Features

- add auto detection for core file format *(Peter Dragun - 05e02af)*

---

## v1.8.0 (2023-11-20)

### ✨ New Features

- **esp-coredump**: increase version to 1.8.0 *(Erhan Kurubas - 460b9d6)*
- **coredump**: print isr context from elf file *(Erhan Kurubas - 52fb6f2)*

---

## v1.7.0 (2023-08-07)

### ✨ New Features

- **esp-coredump**: increase version to 1.7.0 *(Erhan Kurubas - 0b374a4)*
- **coredump**: parse panic_details from elf file *(Erhan Kurubas - 0361906)*

---

## v1.6.0 (2023-07-05)

### 🐛 Bug Fixes

- **coredump-info**: esp32c2/esp32c6/esp32h2 corefile support *(Alexey Lapshin - 7e3f8f7)*

---

## v1.5.2 (2023-06-06)

### ✨ New Features

- **coredump-info**: retry reading thread info if not successful *(Peter Dragun - d69dc03)*

---

## v1.5.1 (2023-05-22)

### 🐛 Bug Fixes

- increase the version of the package *(Aleksei Apaseev - 6fe11bc)*

---

## v1.5.0 (2023-02-21)

### ✨ New Features

- add functionality to load ROM symbols automatically *(Aleksei Apaseev - 6e53888)*

### 🐛 Bug Fixes

- fix isort error *(Aleksei Apaseev - 954501e)*
- update pre-commit flake8 repo *(Aleksei Apaseev - a57a812)*

---

<div align="center">
    <small>
        <b>
            <a href="https://www.github.com/espressif/cz-plugin-espressif">Commitizen Espressif plugin</a>
        </b>
    <br>
        <sup><a href="https://www.espressif.com">Espressif Systems CO LTD. (2025)</a><sup>
    </small>
</div>
