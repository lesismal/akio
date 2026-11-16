#!/bin/sh
# RUSTC_WRAPPER for sanitizer builds with -Zbuild-std (tools/sanitizers/README.md).
#
# Builds compiler_builtins WITHOUT -Zsanitizer. On aarch64 the C++ sanitizer runtimes call
# compiler_builtins' outline-atomics helpers (__aarch64_swp1_acq, ...) while they initialise;
# instrumented, those helpers call back into the not-yet-initialised runtime and every binary
# crashes with SIGSEGV before main (__tsan::TraceSwitchPart from __tsan::Initialize, and the
# ASan equivalent). The prebuilt std is uninstrumented, which is why plain -Zsanitizer=address
# works without -Zbuild-std. The rest of the build then needs
# -Cunsafe-allow-abi-mismatch=sanitizer in RUSTFLAGS, set by run.sh / the CI job.
# Harmless on x86_64, where compiler_builtins has no such helpers.
rustc="$1"
shift
case " $* " in
*" --crate-name compiler_builtins "*)
    args=""
    for a in "$@"; do
        case "$a" in
        -Zsanitizer=*) ;;
        *) args="$args
$a" ;;
        esac
    done
    IFS='
'
    # shellcheck disable=SC2086 # split on newlines only, by design
    set -- $args
    exec "$rustc" "$@" -Cunsafe-allow-abi-mismatch=sanitizer
    ;;
esac
exec "$rustc" "$@"
