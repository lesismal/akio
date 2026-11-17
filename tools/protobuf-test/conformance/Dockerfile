# The protobuf conformance test runner (C++, built from the protobuf release sources) next to a
# Rust toolchain, to run the only-protobuf testee (`tools/protobuf-test/conformance/run.sh`).
FROM debian:bookworm AS runner
ARG PROTOBUF_VERSION=v35.1
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
        ca-certificates cmake g++ git make ninja-build >/dev/null
RUN git clone -q --depth 1 --branch ${PROTOBUF_VERSION} https://github.com/protocolbuffers/protobuf.git /protobuf
RUN cmake -S /protobuf -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -Dprotobuf_BUILD_CONFORMANCE=ON -Dprotobuf_BUILD_TESTS=OFF \
        -Dprotobuf_FORCE_FETCH_DEPENDENCIES=ON -Dprotobuf_INSTALL=OFF >/dev/null \
    && cmake --build /build --target conformance_test_runner -j"$(nproc)" >/dev/null \
    && cp /build/conformance_test_runner /usr/local/bin/

FROM rust:1-bookworm
COPY --from=runner /usr/local/bin/conformance_test_runner /usr/local/bin/
COPY --from=runner /protobuf/conformance/failure_list_cpp.txt /usr/local/share/
