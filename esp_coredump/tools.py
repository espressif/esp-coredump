#
# SPDX-FileCopyrightText: 2022-2023 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
import json


class FatalError(Exception):
    pass


def load_json_from_file(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
    return data
