#!/usr/bin/env bash
# Run the workspace tests under AddressSanitizer or ThreadSanitizer, one crate at a time.
#
#   tools/sanitizers/run.sh address|thread [crate...]       # natively, on Linux with nightly
#   tools/sanitizers/run.sh --docker address|thread [crate...]   # in a Linux container
#
# With no crates, every workspace member with a library or test target is run, except
# akio-dpdk (needs libdpdk). Each crate gets SAN_TIMEOUT seconds (default 1800).
# AKIO_TEST_BACKEND (epoll | uring) is passed through. One log per crate goes to
# $SAN_LOG_DIR (default target/sanitizers/<san>/); a summary line per crate goes to stdout.
# See tools/sanitizers/README.md.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

if [ "${1:-}" = "--docker" ]; then
    shift
    san=${1:?address|thread}
    image=${SAN_IMAGE:-akio-sanitizers}
    docker build -q ${SAN_PLATFORM:+--platform "$SAN_PLATFORM"} -t "$image" "$here" >/dev/null || exit 1
    # seccomp=unconfined: Docker's default profile blocks io_uring_setup(2).
    # memlock=-1: io_uring charges rings and buffer rings to the user's locked_vm, which is
    # shared by every container running as root on the host, against this container's
    # RLIMIT_MEMLOCK (8 MiB by default on Linux Docker); with other io_uring tests running
    # next to this one, ring setup failed with ENOMEM.
    # SAN_TARGET (a named volume or a host path), SAN_NICE and SAN_DOCKER_ARGS let a shared
    # benchmark host keep the run in its own directory and at low priority.
    # shellcheck disable=SC2086 # SAN_DOCKER_ARGS is a list of flags
    exec docker run --rm ${SAN_PLATFORM:+--platform "$SAN_PLATFORM"} --security-opt seccomp=unconfined \
        --ulimit memlock=-1 ${SAN_DOCKER_ARGS:-} \
        -e AKIO_TEST_BACKEND="${AKIO_TEST_BACKEND:-}" \
        -e SAN_LOG_DIR=/work/target/sanitizers/"$san"-"${AKIO_TEST_BACKEND:-epoll}"-docker \
        -e CARGO_TARGET_DIR=/target \
        -v "$root":/work -w /work \
        -v "${SAN_TARGET:-akio-san-target-$san}":/target \
        -v akio-san-cargo:/usr/local/cargo/registry \
        "$image" ${SAN_NICE:+nice -n "$SAN_NICE"} tools/sanitizers/run.sh "$@"
fi

san=${1:?address|thread}
shift
case "$san" in address | thread) ;; *) echo "unknown sanitizer $san" >&2; exit 2 ;; esac
target=$(rustc +nightly -vV | sed -n 's/^host: //p')

export RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-nightly}
export RUSTC_WRAPPER="$here/rustc-wrapper.sh"
export RUSTFLAGS="-Zsanitizer=$san -Cunsafe-allow-abi-mismatch=sanitizer ${SAN_EXTRA_RUSTFLAGS:-}"
export RUSTDOCFLAGS="-Zsanitizer=$san -Cunsafe-allow-abi-mismatch=sanitizer"
sym=$(command -v llvm-symbolizer || find /usr/bin -name 'llvm-symbolizer-*' 2>/dev/null | sort -V | tail -1)
[ -n "$sym" ] && export ASAN_SYMBOLIZER_PATH="$sym" TSAN_SYMBOLIZER_PATH="$sym"
export ASAN_OPTIONS="${ASAN_OPTIONS:-symbolize=1:fast_unwind_on_malloc=0:detect_leaks=1:detect_stack_use_after_return=1}"
# Tests with fixed event deadlines multiply them by this (TSan slows a debug build 5-15x).
export AKIO_TEST_TIMEOUT_SCALE="${AKIO_TEST_TIMEOUT_SCALE:-10}"
export LSAN_OPTIONS="${LSAN_OPTIONS:-suppressions=$here/lsan.supp:print_suppressions=0}"
export TSAN_OPTIONS="${TSAN_OPTIONS:-halt_on_error=1 second_deadlock_stack=1 suppressions=$here/tsan.supp}"

if [ $# -eq 0 ]; then
    set -- $(cd "$root" && cargo metadata --no-deps --format-version 1 |
        python3 -c 'import json,sys; print(" ".join(p["name"] for p in json.load(sys.stdin)["packages"] if p["name"] != "akio-dpdk" and any(k in ("lib", "test") for t in p["targets"] for k in t["kind"])))')
fi
logs=${SAN_LOG_DIR:-$root/target/sanitizers/$san}
mkdir -p "$logs"
fail=0
for c in "$@"; do
    start=$(date +%s)
    # A hang (a deadlock, or a signal TSan never delivers) fails the crate instead of the run.
    (cd "$root" && timeout "${SAN_TIMEOUT:-1800}" cargo test -Zbuild-std --target "$target" -p "$c" --lib --tests ${SAN_CARGO_ARGS:-} \
        -- --test-threads="${SAN_TEST_THREADS:-1}") >"$logs/$c.log" 2>&1
    rc=$?
    reports=$(grep -c -E '^(WARNING: ThreadSanitizer|==[0-9]+==ERROR: (Address|Leak)Sanitizer)' "$logs/$c.log")
    echo "$c rc=$rc reports=$reports $(( $(date +%s) - start ))s"
    [ "$rc" -ne 0 ] && fail=1
done
exit $fail
