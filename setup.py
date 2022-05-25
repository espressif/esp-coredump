#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#

import io
import os
import re

from setuptools import find_packages, setup

NAME = 'esp-coredump'
DESCRIPTION = 'Generate core dumps on unrecoverable software errors'
URL = 'https://github.com/espressif/esp-idf'
EMAIL = 'aleksei.apaseev@espressif.com'
AUTHOR = 'Espressif Systems'
REQUIRES_PYTHON = '>=3.6.0'
REQUIRED = ['construct~=2.10', 'pygdbmi>=0.9.0.2', 'esptool']

cur_dir_path = os.path.abspath(os.path.dirname(__file__))
init_file_path = './esp_coredump/__init__.py'
try:
    with open(os.path.join(cur_dir_path, 'README.md'), encoding='utf-8') as f:
        long_description = '\n' + f.read()
except FileNotFoundError:
    long_description = DESCRIPTION


def read(*names, **kwargs):
    with io.open(
            os.path.join(os.path.dirname(__file__), *names),
            encoding=kwargs.get('encoding', 'utf8')
    ) as fp:
        return fp.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError('Unable to find version string.')


setup(
    name=NAME,
    version=find_version(init_file_path),
    description=DESCRIPTION,
    long_description=long_description,
    long_description_content_type='text/markdown',
    author=AUTHOR,
    author_email=EMAIL,
    python_requires=REQUIRES_PYTHON,
    url=URL,
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'esp-coredump = esp_coredump.scripts.espcoredump:main'
        ],
    },
    install_requires=REQUIRED,
    license='Apache 2.0',
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3 :: Only',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: Apache Software License',
    ],
)
