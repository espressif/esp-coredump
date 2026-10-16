/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */
#include <stdint.h>
#include "sdkconfig.h"
#include "esp_attr.h"

#if CONFIG_TEST_PRINT_VARS
/* Tagged C++ variables for --print-all-vars */
namespace batt {
COREDUMP_DRAM_ATTR uint32_t g_cpp_ns_var;
}

namespace {
COREDUMP_DRAM_ATTR __attribute__((used)) uint32_t s_cpp_anon_var;
}

static COREDUMP_DRAM_ATTR __attribute__((used)) uint32_t s_cpp_file_static;

struct cpp_cfg_t {
    static uint32_t s_member;
};
COREDUMP_DRAM_ATTR uint32_t cpp_cfg_t::s_member;

extern "C" void set_cpp_tagged_vars(void)
{
    static COREDUMP_DRAM_ATTR __attribute__((used)) uint32_t s_cpp_func_static;

    s_cpp_func_static = 0x22220004;
    batt::g_cpp_ns_var = 0x22220001;
    s_cpp_anon_var = 0x22220002;
    s_cpp_file_static = 0x22220005;
    cpp_cfg_t::s_member = 0x22220003;
}
#endif
