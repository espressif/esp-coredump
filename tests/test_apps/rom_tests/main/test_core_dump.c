/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_chip_info.h"
#include "esp_flash.h"


void fail_once(char unused) {
    static int first = 1;
    if (first) {
        first = 0;
        abort();
    }
}

void app_main(void) {
    printf("Hello world!\n");
    esp_rom_install_channel_putc(2, fail_once);
    esp_rom_printf("a");
}
