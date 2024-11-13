# SPDX-FileCopyrightText: 2022-2024 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
import base64
import contextlib
import io
import os

import pytest

try:
    from esp_coredump import CoreDump
    from esp_coredump.corefile import ESPCoreDumpLoaderError
    from esp_coredump.corefile.elf import ESPCoreDumpElfFile
    from esp_coredump.corefile.loader import ESPCoreDumpFileLoader
except ImportError:
    raise ModuleNotFoundError('No module named "esp_coredump" please install esp_coredump by running '
                              '"python -m pip install esp-coredump"')

SUPPORTED_TARGET = ['esp32', 'esp32c3', 'esp32p4']
COREDUMP_FILE_NAME = 'coredump'

TEST_DIR_ABS_PATH = os.path.dirname(__file__)
ESP_PROG_DIR = os.path.join(TEST_DIR_ABS_PATH, 'test_apps', 'built_apps')


def get_coredump_kwargs(core_ext: str, target: str, save_core: bool = False, auto_format: bool = False):
    core_format = 'auto' if auto_format else 'raw' if core_ext == 'bin' else core_ext
    kwargs = {
        'gdb_timeout_sec': 5,
        'chip': target,
        'print_mem': True,
        'core_format': core_format,
        'core': os.path.join(TEST_DIR_ABS_PATH, target, f'{COREDUMP_FILE_NAME}.{core_ext}'),
        'save_core': os.path.join(TEST_DIR_ABS_PATH, target, f'{COREDUMP_FILE_NAME}.elf') if save_core else None,
        'prog': os.path.join(ESP_PROG_DIR, f'{target}.elf'),
    }
    return kwargs


def get_expected_output(target: str):
    expected_output_file = os.path.join(TEST_DIR_ABS_PATH, target, 'expected_output')
    with open(expected_output_file) as file:
        output = file.read()
    return output


def get_output(core_ext: str, target: str, save_core: bool = False, auto_format: bool = False):
    kwargs = get_coredump_kwargs(core_ext=core_ext, save_core=save_core, target=target, auto_format=auto_format)
    coredump = CoreDump(**kwargs)
    output_file = os.path.join(TEST_DIR_ABS_PATH, target, f'output_from_{core_ext}')
    with io.StringIO() as buffer, contextlib.redirect_stdout(buffer):
        coredump.info_corefile()
        output = buffer.getvalue()

    with open(output_file, 'w') as f:
        f.write(output)
    return output


def decode_from_b64_to_bin(target):
    b64_file_path = os.path.join(TEST_DIR_ABS_PATH, target, f'{COREDUMP_FILE_NAME}.b64')
    bin_file_path = os.path.join(TEST_DIR_ABS_PATH, target, f'{COREDUMP_FILE_NAME}.bin')
    with open(b64_file_path, 'rb') as fb64, open(bin_file_path, 'wb') as fw:
        for line in fb64:
            data = base64.standard_b64decode(line.rstrip(b'\r\n'))
            fw.write(data)


class TestESPCoreDumpDecode:

    @pytest.mark.parametrize('target', SUPPORTED_TARGET)
    def test_coredump_decode_from_b64(self, target):
        output = get_output(core_ext='b64', save_core=True, target=target)
        expected_output = get_expected_output(target)
        assert expected_output == output

    @pytest.mark.parametrize('target', SUPPORTED_TARGET)
    def test_coredump_decode_from_elf(self, target):
        output = get_output(core_ext='elf', target=target)
        expected_output = get_expected_output(target)
        assert expected_output == output

    @pytest.mark.parametrize('target', SUPPORTED_TARGET)
    def test_coredump_decode_from_bin(self, target):
        decode_from_b64_to_bin(target)
        output = get_output(core_ext='bin', target=target)
        expected_output = get_expected_output(target)
        assert expected_output == output

    @pytest.mark.parametrize('format', ['bin', 'elf', 'b64'])
    @pytest.mark.parametrize('target', SUPPORTED_TARGET)
    def test_coredump_decode_auto_format(self, target, format):
        # make sure that .elf and .bin inputs are created
        get_output(core_ext='b64', save_core=True, target=target)
        decode_from_b64_to_bin(target)
        output = get_output(core_ext=format, target=target, auto_format=True)
        expected_output = get_expected_output(target)
        assert expected_output == output


class TestESPCoreDumpElfFile:
    @pytest.mark.parametrize('target', SUPPORTED_TARGET)
    def test_read_elf(self, target):
        elf = ESPCoreDumpElfFile(os.path.join(TEST_DIR_ABS_PATH, target, f'{COREDUMP_FILE_NAME}.elf'))
        assert elf.load_segments is not None
        assert elf.note_segments is not None


class TestESPCoreDumpFileLoader:
    @pytest.mark.parametrize('target', SUPPORTED_TARGET)
    def test_load_wrong_encode_core_bin(self, target):
        with pytest.raises(ESPCoreDumpLoaderError):
            ESPCoreDumpFileLoader(path=os.path.join(TEST_DIR_ABS_PATH, target, f'{COREDUMP_FILE_NAME}.b64'), is_b64=False)

    @pytest.mark.parametrize('target', SUPPORTED_TARGET)
    def test_create_corefile(self, target):
        loader = ESPCoreDumpFileLoader(path=os.path.join(TEST_DIR_ABS_PATH, target, f'{COREDUMP_FILE_NAME}.b64'), is_b64=True)
        loader.create_corefile()
        assert os.path.exists(loader.core_elf_file)
