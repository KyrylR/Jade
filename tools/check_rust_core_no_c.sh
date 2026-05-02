#!/usr/bin/env bash
set -euo pipefail

if find crates -type f \( \
    -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o \
    -name '*.h' -o -name '*.hh' -o -name '*.hpp' -o -name '*.hxx' \
  \) | grep -q .; then
  echo "C/C++ files are not allowed under crates/." >&2
  find crates -type f \( \
      -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o \
      -name '*.h' -o -name '*.hh' -o -name '*.hpp' -o -name '*.hxx' \
    \) >&2
  exit 1
fi

