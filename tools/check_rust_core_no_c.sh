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

if command -v cargo >/dev/null 2>&1; then
  forbidden_deps="$(cargo tree --workspace --all-features --target all --prefix none \
    | grep -E '^(bindgen|cc|cmake|cxx|secp256k1-sys) v' || true)"
  if [ -n "${forbidden_deps}" ]; then
    echo "C/C++ build or FFI dependencies are not allowed in the active Rust core tree." >&2
    echo "${forbidden_deps}" >&2
    exit 1
  fi
fi
