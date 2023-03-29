# SPDX-FileCopyrightText: 2022-2023 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
import base64
import contextlib
import io
import os
import unittest

try:
    from esp_coredump import CoreDump
    from esp_coredump.corefile import ESPCoreDumpLoaderError
    from esp_coredump.corefile.elf import ESPCoreDumpElfFile
    from esp_coredump.corefile.loader import ESPCoreDumpFileLoader
except ImportError:
    raise ModuleNotFoundError('No module named "esp_coredump" please install esp_coredump by running '
                              '"python -m pip install esp-coredump"')

SUPPORTED_TARGET = ['esp32', 'esp32c3']
APP_TYPE = ['with_rom', 'without_rom']
COREDUMP_FILE_NAME = 'coredump'

ESP_ROM_ELF_DIR = os.getenv('ESP_ROM_ELF_DIR')

TEST_DIR_ABS_PATH = os.path.dirname(__file__)
ESP_PROG_DIR = os.path.join(TEST_DIR_ABS_PATH, 'test_apps', 'built_apps')


def get_app_dir(app_type):
    return '.' if app_type == 'without_rom' else 'rom_tests'


def get_coredump_kwargs(core_ext: str, app_type: str, target: str, save_core=False):
    if app_type == 'with_rom' and ESP_ROM_ELF_DIR is None:
        raise ValueError('Please set the environment variable ESP_ROM_ELF_DIR, '
                         'which specifies the location of the ROM ELF files.')
    if ESP_PROG_DIR is None:
        raise ValueError('Please set the environment variable ESP_PROG_DIR, '
                         "which specifies the location of the directory where the program\'s ELF binary stored")
    core_format = 'raw' if core_ext == 'bin' else core_ext
    app_dir = get_app_dir(app_type)
    kwargs = {
        'gdb_timeout_sec': 5,
        'chip': target,
        'print_mem': True,
        'core_format': core_format,
        'core': os.path.join(TEST_DIR_ABS_PATH, app_dir, target, f'{COREDUMP_FILE_NAME}.{core_ext}'),
        'save_core': os.path.join(TEST_DIR_ABS_PATH, app_dir, target, f'{COREDUMP_FILE_NAME}.elf') if save_core else None,
        'prog': os.path.join(ESP_PROG_DIR, app_dir, f'{target}.elf'),
    }
    return kwargs


def get_expected_output(app_type: str, target: str):
    app_dir = get_app_dir(app_type)
    expected_output_file = os.path.join(TEST_DIR_ABS_PATH, app_dir, target, 'expected_output')
    with open(expected_output_file) as file:
        output = file.read()
    return output


def get_output(core_ext: str, app_type: str, target: str, save_core=False):
    kwargs = get_coredump_kwargs(core_ext=core_ext, save_core=save_core, app_type=app_type, target=target)
    coredump = CoreDump(**kwargs)
    app_dir = get_app_dir(app_type)
    output_file = os.path.join(TEST_DIR_ABS_PATH, app_dir, target, f'output_from_{core_ext}')
    with io.StringIO() as buffer, contextlib.redirect_stdout(buffer):
        coredump.info_corefile()
        output = buffer.getvalue()

    with open(output_file, 'w') as f:
        f.write(output)
    return output


def decode_from_b64_to_bin(app_type, target):
    app_dir = get_app_dir(app_type)
    b64_file_path = os.path.join(TEST_DIR_ABS_PATH, app_dir, target, f'{COREDUMP_FILE_NAME}.b64')
    bin_file_path = os.path.join(TEST_DIR_ABS_PATH, app_dir, target, f'{COREDUMP_FILE_NAME}.bin')
    with open(b64_file_path, 'rb') as fb64, open(bin_file_path, 'wb') as fw:
        for line in fb64:
            data = base64.standard_b64decode(line.rstrip(b'\r\n'))
            fw.write(data)


class TestESPCoreDumpDecode(unittest.TestCase):
    def test_coredump_decode_from_b64(self):
        for app_type in APP_TYPE:
            for target in SUPPORTED_TARGET:
                output = get_output(core_ext='b64', save_core=True, app_type=app_type, target=target)
                expected_output = get_expected_output(app_type, target)
                self.assertEqual(expected_output, output)

    def test_coredump_decode_from_elf(self):
        for app_type in APP_TYPE:
            for target in SUPPORTED_TARGET:
                output = get_output(core_ext='elf', app_type=app_type, target=target)
                expected_output = get_expected_output(app_type, target)
                self.assertEqual(expected_output, output)

    def test_coredump_decode_from_bin(self):
        for app_type in APP_TYPE:
            for target in SUPPORTED_TARGET:
                decode_from_b64_to_bin(app_type, target)
                output = get_output(core_ext='bin', app_type=app_type, target=target)
                expected_output = get_expected_output(app_type, target)
                self.assertEqual(expected_output, output)


class TestESPCoreDumpElfFile(unittest.TestCase):
    def test_read_elf(self):
        for app_type in APP_TYPE:
            for target in SUPPORTED_TARGET:
                app_dir = get_app_dir(app_type)
                elf = ESPCoreDumpElfFile(os.path.join(TEST_DIR_ABS_PATH, app_dir, target, f'{COREDUMP_FILE_NAME}.elf'))
                self.assertIsNotNone(elf.load_segments)
                self.assertIsNotNone(elf.note_segments)


class TestESPCoreDumpFileLoader(unittest.TestCase):
    def test_load_wrong_encode_core_bin(self):
        for app_type in APP_TYPE:
            for target in SUPPORTED_TARGET:
                app_dir = get_app_dir(app_type)
                with self.assertRaises(ESPCoreDumpLoaderError):
                    ESPCoreDumpFileLoader(path=os.path.join(TEST_DIR_ABS_PATH, app_dir, target, f'{COREDUMP_FILE_NAME}.b64'), is_b64=False)

    def test_create_corefile(self):
        for app_type in APP_TYPE:
            for target in SUPPORTED_TARGET:
                app_dir = get_app_dir(app_type)
                loader = ESPCoreDumpFileLoader(path=os.path.join(TEST_DIR_ABS_PATH, app_dir, target, f'{COREDUMP_FILE_NAME}.b64'), is_b64=True)
                loader.create_corefile()
                self.assertTrue(os.path.exists(loader.core_elf_file))
