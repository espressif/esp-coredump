#
# SPDX-FileCopyrightText: 2022-2023 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import re
import time
from subprocess import TimeoutExpired

from pygdbmi.gdbcontroller import GdbController

from esp_coredump.log import log

from . import ESPCoreDumpError

DEFAULT_GDB_TIMEOUT_SEC = 3

try:
    # pygdbmi>=0.10.0.2 decodes stream payloads
    import pygdbmi.gdbescapes  # noqa: F401

    STREAM_PAYLOAD_DECODED = True
except ImportError:
    STREAM_PAYLOAD_DECODED = False


def mi_escape(text):
    """Escape text for a GDB/MI quoted string"""
    return text.replace('\\', '\\\\').replace('"', '\\"')


def mi_unescape(text):
    """Decode a GDB/MI quoted string. Octal escapes are bytes of a UTF-8 string."""
    simple = {'n': '\n', 't': '\t', 'r': '\r', 'a': '\a', 'b': '\b', 'f': '\f', 'v': '\v', 'e': '\x1b'}
    out = bytearray()
    for part in re.split(r'(\\(?:[0-7]{1,3}|.))', text):
        if len(part) > 1 and part[0] == '\\':
            esc = part[1:]
            out += bytes([int(esc, 8) & 0xFF]) if esc[0] in '01234567' else simple.get(esc, esc).encode()
        else:
            out += part.encode()
    return out.decode('utf-8', 'replace')


class EspGDB:
    def __init__(self, gdb_args, timeout_sec=DEFAULT_GDB_TIMEOUT_SEC):
        """
        Start GDB and initialize a GdbController instance
        """
        try:
            self.p = GdbController(command=gdb_args)
        except TypeError:
            # fallback for pygdbmi<0.10.0.0.
            self.p = GdbController(gdb_path=gdb_args[0], gdb_args=gdb_args[1:])

        self.timeout = timeout_sec
        self.token = 0

        # Consume initial output by issuing a dummy command
        self._run_mi('-data-list-register-values x pc')

    def __del__(self):
        """
        EspGDB destructor taking GdbController.gdb_process.exit() and adjusting it
        to work properly
        """
        try:
            if self.p.gdb_process:
                self.p.gdb_process.terminate()
                if os.name != 'nt':
                    # this is causing an Exception on Windows,
                    # but is required on UNIX systems
                    # Close pipes (STDIN, STDOUT, STDERR)
                    self.p.gdb_process.communicate()
                try:
                    self.p.gdb_process.wait(timeout=1)
                except TimeoutExpired:
                    if self.p.gdb_process.returncode is None:
                        self.p.gdb_process.kill()
                self.p.gdb_process = None
        except IndexError:
            log.warn('Attempt to terminate the GDB process failed, because it is already terminated. Skip.')

    def _gdbmi_data_evaluate_expression(self, expr):
        """Get the value of an expression, similar to the 'print' command"""
        value, error = self.evaluate(expr)
        if error:
            raise ESPCoreDumpError(error)
        return value

    def get_tcb_variable(self, tcb_addr, variable):
        """Get FreeRTOS variable from given TCB address"""
        try:
            val = self._gdbmi_data_evaluate_expression(f'(char*)((TCB_t *)0x{tcb_addr:x})->{variable}')
        except (ESPCoreDumpError, KeyError):
            # KeyError is raised when "value" is not in "payload"
            return ''
        return val

    def parse_tcb_variable(self, tcb_addr, variable):
        """Get FreeRTOS variable from given TCB address"""
        val = self.get_tcb_variable(tcb_addr, variable)

        # Value is of form '0x12345678 ""'
        result = re.search(r'0x[0-9a-fA-F]+', val)
        if result:
            return result.group(0)
        return ''

    def get_freertos_task_name(self, tcb_addr):
        """Get FreeRTOS task name given the TCB address"""
        val = self.get_tcb_variable(tcb_addr, 'pcTaskName')

        # Value is of form '0x12345678 "task_name"', extract the actual name
        result = re.search(r"\"([^']*)\"$", val)
        if result:
            return result.group(1)
        return ''

    def run_cmd(self, gdb_cmd):
        """Execute a generic GDB console command via MI2"""
        _, text, _ = self._run_mi(f'-interpreter-exec console "{mi_escape(gdb_cmd)}"')
        return text.rstrip('\n')

    def _run_mi(self, cmd, timeout_sec=None):
        """Run an MI command and return (result payload, console text, error)"""
        # A token links the result to this command, not to an earlier one that timed out
        self.token += 1
        self.p.write(f'{self.token}{cmd}', read_response=False)
        console = []
        t_end = time.time() + (timeout_sec or self.timeout)
        while time.time() < t_end:
            for rsp in self.p.get_gdb_response(timeout_sec=0, raise_error_on_timeout=False):
                if rsp['type'] == 'console':
                    console.append(rsp['payload'])
                elif rsp['type'] == 'result' and rsp.get('token') != self.token:
                    console = []
                elif rsp['type'] == 'result':
                    text = ''.join(console)
                    text = text if STREAM_PAYLOAD_DECODED else mi_unescape(text)
                    if rsp['message'] == 'error':
                        return None, text, rsp['payload']['msg']
                    return rsp['payload'], text, None
        return None, '', 'GDB did not respond'

    def evaluate(self, expr, fmt=None):
        """Evaluate an expression with GDB "output[/fmt]" and return (value, error)"""
        # Console output, not -data-evaluate-expression: pygdbmi<0.10 drops octal escapes in result values
        cmd = f'output/{fmt} {expr}' if fmt else f'output {expr}'
        _, text, error = self._run_mi(f'-interpreter-exec console "{mi_escape(cmd)}"')
        return (None if error else text), error

    def get_architecture(self):
        """Get the architecture name GDB uses now, or None"""
        result = re.search(r'(?:currently|set to) "([^"]+)"\)?\.?$', self.run_cmd('show architecture'))
        return result.group(1) if result else None

    def set_exec_file(self, path=None):
        """Load the program ELF, or unload it when path is None. Return the GDB error, if any."""
        cmd = 'exec-file'
        if path:
            path = os.path.abspath(path)
            if os.name == 'nt':
                path = path.replace('\\', '/')
            # GDB quotes file names with the same escapes as MI
            cmd += f' "{mi_escape(path)}"'
        _, _, error = self._run_mi(f'-interpreter-exec console "{mi_escape(cmd)}"')
        return error

    def get_thread_info(self, response_delay_sec=DEFAULT_GDB_TIMEOUT_SEC):
        """Get information about all threads known to GDB, and the current thread ID"""
        result, _, error = self._run_mi('-thread-info', response_delay_sec)
        if error or not result:
            return None, None

        current_thread_id = result['current-thread-id']
        threads = result['threads']
        return threads, current_thread_id

    def switch_thread(self, thr_id):
        """Tell GDB to switch to a specific thread, given its ID"""
        _, _, error = self._run_mi(f'-thread-select {thr_id}')
        if error:
            raise ESPCoreDumpError(error)

    @staticmethod
    def gdb2freertos_thread_id(gdb_target_id):
        """Convert GDB 'target ID' to the FreeRTOS TCB address"""
        return int(gdb_target_id.replace('process ', ''), 0)
