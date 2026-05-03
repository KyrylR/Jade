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
  cargo_tree="$(cargo tree --workspace --all-features --target all --prefix none)"
  forbidden_deps="$(printf '%s\n' "${cargo_tree}" \
    | grep -E '^(bindgen|cmake|cxx) v' || true)"
  if [ -n "${forbidden_deps}" ]; then
    echo "C/C++ build or FFI dependencies are not allowed in the active Rust core tree." >&2
    echo "${forbidden_deps}" >&2
    exit 1
  fi
  liquid_backend_deps="$(printf '%s\n' "${cargo_tree}" \
    | grep -E '^(cc|secp256k1-sys|secp256k1-zkp-sys) v' \
    | sed 's/ (\*)$//' \
    | sort -u || true)"
  if [ -n "${liquid_backend_deps}" ] \
      && ! printf '%s\n' "${cargo_tree}" | grep -q -E '^elements v'; then
    echo "Unexpected C/C++ build or FFI dependencies are present." >&2
    echo "${liquid_backend_deps}" >&2
    exit 1
  fi
  if [ -n "${liquid_backend_deps}" ]; then
    echo "Allowing permanent upstream Elements/secp256k1-zkp Liquid backend:" >&2
    echo "${liquid_backend_deps}" >&2
  fi
fi
