/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */
#include <stdlib.h>
#include "esp_rom_sys.h"


void fail_once(char unused) {
    static int first = 1;
    if (first) {
        first = 0;
        abort();
    }
}

void app_main(void) {
    esp_rom_install_channel_putc(2, fail_once);
    esp_rom_printf("a");
}
