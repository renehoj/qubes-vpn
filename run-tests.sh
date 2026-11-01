#!/bin/sh
# Run the qubes-vpn test suite. Stdlib unittest only, no third-party deps.
#
# Does NOT use "python3 -m unittest discover". Discovery refuses a start
# directory that is not an importable package: with "-s tests -t ." it requires
# tests/__init__.py to exist, and if that file is ever missing (a partial copy,
# a stripped tarball, a filesystem that ate an empty-ish file) you get an opaque
# "ImportError: Start directory is not importable" instead of a test result.
#
# Every test module carries its own sys.path shim and a unittest.main() guard,
# so running them as scripts is layout-independent and version-independent.
set -u
cd "$(dirname "$0")"

failed=0
ran=0
for test_file in tests/test_*.py; do
    [ -e "$test_file" ] || continue
    ran=$((ran + 1))
    printf '\n=== %s\n' "$test_file"
    if ! python3 "$test_file"; then
        failed=$((failed + 1))
    fi
done

if [ "$ran" -eq 0 ]; then
    printf '\nNo test modules found under tests/\n' >&2
    exit 1
fi

if [ "$failed" -ne 0 ]; then
    printf '\nFAILED: %d of %d test module(s) did not pass\n' "$failed" "$ran"
    exit 1
fi

printf '\nAll %d test modules passed\n' "$ran"
