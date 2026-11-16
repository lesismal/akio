# Nightly Rust with rust-src (for -Zbuild-std) and llvm-symbolizer, for tools/sanitizers/run.sh.
FROM rustlang/rust:nightly
# The image's toolchain is named nightly-<date>-<host>; expose it as plain `nightly` (what
# run.sh asks for, overriding rust-toolchain.toml) so rustup does not download a second one.
RUN rustup component add rust-src \
    && cd /usr/local/rustup/toolchains && t=$(ls) && ln -s "$t" "nightly-${t#nightly-????-??-??-}" \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends llvm python3 >/dev/null \
    && rm -rf /var/lib/apt/lists/*
