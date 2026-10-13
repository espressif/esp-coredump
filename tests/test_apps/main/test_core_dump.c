/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */
#include <stdlib.h>
#include "esp_attr.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"


#if CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY == 1 || CONFIG_ESP_SYSTEM_ALLOW_RTC_FAST_MEM_AS_HEAP == 1
#define TEST_TASK_STACK_SIZE 4096

void test_task(void *arg)
{
    (void)arg;
    uint32_t notify_value;
    xTaskNotifyWait(0x0, 0xFFFFFFFF, &notify_value, portMAX_DELAY);
    vTaskDelete(NULL);
}

void create_task_use_cap(const char *task_name, uint32_t stack_caps)
{
    StaticTask_t *task_tcb = heap_caps_calloc(1, sizeof(StaticTask_t), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    StackType_t *task_stack = heap_caps_malloc(TEST_TASK_STACK_SIZE, stack_caps);
    xTaskCreateStaticPinnedToCore(test_task, task_name, TEST_TASK_STACK_SIZE, NULL, 15, task_stack, task_tcb, 0);
}
#endif

#if CONFIG_TEST_PRINT_VARS
typedef struct {
    uint32_t mv;
    uint32_t busy : 1;
} batt_t;

/* Tagged variables for --print-all-vars */
COREDUMP_DRAM_ATTR batt_t g_batt;
static COREDUMP_DRAM_ATTR uint32_t s_dram_static;
#if CONFIG_SOC_RTC_FAST_MEM_SUPPORTED || CONFIG_SOC_RTC_SLOW_MEM_SUPPORTED
COREDUMP_RTC_DATA_ATTR uint32_t g_rtc_var;
#endif
COREDUMP_NOINIT_ATTR uint32_t g_noinit_var;

static void set_tagged_vars(void)
{
    static COREDUMP_DRAM_ATTR __attribute__((used)) uint32_t s_func_static;

    s_func_static = 0x11110004;
    g_batt.mv = 3712;
    g_batt.busy = 1;
    s_dram_static = 0x11110001;
#if CONFIG_SOC_RTC_FAST_MEM_SUPPORTED || CONFIG_SOC_RTC_SLOW_MEM_SUPPORTED
    g_rtc_var = 0x11110002;
#endif
    g_noinit_var = 0x11110003;
}

void set_cpp_tagged_vars(void);
#endif

void fail_once(char unused)
{
    static int first = 1;
    if (first) {
        first = 0;
        abort();
    }
}

void app_main(void)
{
#if CONFIG_TEST_PRINT_VARS
    set_tagged_vars();
    set_cpp_tagged_vars();
#endif

#if CONFIG_ESP_SYSTEM_ALLOW_RTC_FAST_MEM_AS_HEAP == 1
    create_task_use_cap("rtc_fast", MALLOC_CAP_8BIT | MALLOC_CAP_RTCRAM);
#endif

#if CONFIG_SPIRAM_ALLOW_STACK_EXTERNAL_MEMORY == 1
    create_task_use_cap("ext_ram", MALLOC_CAP_8BIT | MALLOC_CAP_SPIRAM);
#endif

    esp_rom_install_channel_putc(2, fail_once);
    esp_rom_printf("a");
    vTaskDelete(NULL);
}
