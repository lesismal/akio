#!/usr/bin/env bash
# Runs every fuzz target for SECS seconds (default 300), PAR at a time (default: CPUs), each on
# a scratch corpus seeded from fuzz/corpus/<target>; new inputs land in fuzz/corpus-new/<target>
# (gitignored) and crashes in fuzz/artifacts/<target>. Needs nightly and cargo-fuzz.
#
#   fuzz/run-all.sh [SECS] [PAR] [target...]
#
# Afterwards, `fuzz/run-all.sh merge` minimizes corpus-new back into fuzz/corpus.
set -u
cd "$(dirname "$0")"
TOOLCHAIN=${TOOLCHAIN:-+nightly}
if [ "${1:-}" = merge ]; then
    shift
    for t in ${@:-$(cargo $TOOLCHAIN fuzz list)}; do
        [ -d "corpus-new/$t" ] || continue
        mkdir -p "corpus/$t.min"
        cargo $TOOLCHAIN fuzz run "$t" "corpus/$t.min" "corpus/$t" "corpus-new/$t" -- \
            -merge=1 -rss_limit_mb=4096 >"logs/$t.merge.log" 2>&1
        rm -rf "corpus/$t" && mv "corpus/$t.min" "corpus/$t"
        echo "$t: $(ls "corpus/$t" | wc -l) files"
    done
    exit 0
fi
SECS=${1:-300}
PAR=${2:-$(nproc)}
shift 2 2>/dev/null || shift $#
TARGETS=${*:-$(cargo $TOOLCHAIN fuzz list)}
cargo $TOOLCHAIN fuzz build >/dev/null 2>&1 || cargo $TOOLCHAIN fuzz build
mkdir -p logs corpus-new
run() {
    t=$1
    mkdir -p "corpus-new/$t"
    dict=()
    case $t in
        http1_*) dict=(-dict=dict/http.dict) ;;
    esac
    cargo $TOOLCHAIN fuzz run "$t" "corpus-new/$t" "corpus/$t" -- \
        -max_total_time="$SECS" -rss_limit_mb=2048 -timeout=10 -max_len=8192 \
        -print_final_stats=1 "${dict[@]}" >"logs/$t.log" 2>&1
    rc=$?
    execs=$(grep -m1 'stat::number_of_executed_units' "logs/$t.log" | awk '{print $2}')
    echo "$t rc=$rc execs=${execs:-?}"
}
export -f run
export SECS TOOLCHAIN
printf '%s\n' $TARGETS | xargs -P "$PAR" -I{} bash -c 'run {}'
