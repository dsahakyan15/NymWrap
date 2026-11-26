# Build tools only; neither this image nor its network is used by NymWrap at runtime.
# linux/amd64 manifests resolved from the official Docker registry, 2026-11-26.
FROM node:24.11.1-bookworm-slim@sha256:44b49d6e2d23f6754fb084ef9d34ff14590343ad1ee168f8acf8f7bc9fccde2f AS node
FROM rust:1.100.0-bookworm@sha256:30a9c647e188457aac6e0bd3f9d73ae725dc3f36e57a2808ba3dde653c7c6db8
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* \
    && printf '%s\n' \
       'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261125T000000Z/ bookworm main' \
       'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261125T000000Z/ bookworm-security main' \
       > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       cmake clang libclang-dev pkg-config libssl-dev libdbus-1-dev \
       libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add --toolchain 1.100.0 rustfmt clippy
COPY build.sh /usr/local/bin/nymwrap-release-build
ENV CARGO_BUILD_JOBS=4 CMAKE_BUILD_PARALLEL_LEVEL=4 CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR=/build/target TZ=UTC LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    RUSTFLAGS="--remap-path-prefix=/build=/nymwrap -C target-cpu=x86-64" \
    CFLAGS="-ffile-prefix-map=/build=/nymwrap -fdebug-prefix-map=/build=/nymwrap -march=x86-64 -mtune=generic" \
    CXXFLAGS="-ffile-prefix-map=/build=/nymwrap -fdebug-prefix-map=/build=/nymwrap -march=x86-64 -mtune=generic" \
    ZERO_AR_DATE=1
ENTRYPOINT ["bash", "/usr/local/bin/nymwrap-release-build"]
