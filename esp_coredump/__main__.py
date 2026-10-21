#
# SPDX-FileCopyrightText: 2022-2024 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#

from esp_pylib.excepthook import install_exception_reporting

from esp_coredump.cli_ext import cli


def main():
    install_exception_reporting()
    cli()


if __name__ == '__main__':
    main()
