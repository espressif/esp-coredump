#
# SPDX-FileCopyrightText: 2022-2023 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#


import os
import sys
import unittest

try:
    import esp_coredump
except ImportError:
    raise ModuleNotFoundError('No module named "esp_coredump" please install esp_coredump by running '
                              '"python -m pip install esp-coredump"')

TESTS_DIR = os.path.join(os.path.dirname(os.path.dirname(esp_coredump.__file__)), 'tests')


def main():
    test_suite = unittest.defaultTestLoader.discover(TESTS_DIR, pattern='test*.py')
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    if not result.wasSuccessful():
        sys.exit(1)


if __name__ == '__main__':
    main()
