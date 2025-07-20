#!/usr/bin/env bash

supported_targets=("esp32" "esp32c3" "esp32p4", "esp32c6")
abs_path_build_dir=$(realpath "$(dirname "$0")")
echo "$abs_path_build_dir"

if [ -z "$1" ]
  then
    output_dir="$(realpath "$(dirname "$1")")"
else
    output_dir="$1"
fi
echo "$output_dir"



for chip in "${supported_targets[@]}"; do
  echo "${output_dir}/${chip}/${chip}.elf"
  echo "--------------------------"
  echo "Building $chip binaries..."
  echo "--------------------------"

  cd "$abs_path_build_dir/test_apps"
  idf.py fullclean && rm -f sdkconfig
  idf.py set-target "$chip"
  idf.py build
  if [ ! -d "${output_dir}/${chip}" ]; then
    mkdir -p "${output_dir}/${chip}"
  fi

  cp "$abs_path_build_dir/test_apps/build/test_core_dump.elf" "${output_dir}/${chip}/${chip}.elf" || (echo "can't copy app." && exit 1)
  echo "copied to ${output_dir}/${chip}/${chip}.elf"
done
echo "--------------------------"
echo "Building apps finished..."
echo "--------------------------"
