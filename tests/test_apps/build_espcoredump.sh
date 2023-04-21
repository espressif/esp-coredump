#!/usr/bin/env bash

function display_usage() {
  echo "Usage: bash build_espcoredump.sh [OUTPUT_DIR]"
}

output_dir=${1:?$(display_usage && exit 1)}
supported_targets=("esp32" "esp32c3")
app_types=("with_rom" "without_rom")
save_app_subdir="rom_test_apps"
rm -rf "${output_dir}/${save_app_subdir}" && mkdir "${output_dir}/${save_app_subdir}"


for app_type in "${app_types[@]}"; do
  if [ $(echo "$ESP_IDF_VERSION >= 5.1" | bc -l) -eq 1 ]; then
    if [[ "$app_type" == "without_rom" ]]; then
      continue
    else
      app_subdir="rom_tests"
    fi
  fi
  if [ $(echo "$ESP_IDF_VERSION < 5.1" | bc -l) -eq 1 ]; then
    if [[ "$app_type" == "with_rom" ]]; then
      continue
    else
      app_subdir="."
    fi
  fi

  abs_path_build_dir=$(realpath "$(dirname "$0")/${app_subdir}")

  cd "$abs_path_build_dir" || (echo "can't build app. '$abs_path_build_dir' directory is not found" && exit 1)

  for chip in "${supported_targets[@]}"; do
    echo "--------------------------"
    echo "Building $chip binaries..."
    echo "--------------------------"

    idf.py fullclean && rm -f sdkconfig
    idf.py set-target "$chip"
    idf.py build

    cp "$abs_path_build_dir/build/test_core_dump.elf" "${output_dir}/${save_app_subdir}/${chip}.elf" || (echo "can't copy app." && exit 1)
    echo "copied to ${output_dir}${save_app_subdir}/${chip}.elf"
  done
done
echo "--------------------------"
echo "Building apps finished..."
echo "--------------------------"
