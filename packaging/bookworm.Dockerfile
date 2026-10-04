# Pin Rust and Debian 12 userspace; update this digest through dependency review.
FROM rust:1.94.1-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55

RUN apt-get update \
    && apt-get install -y --no-install-recommends binutils libsqlite3-dev pkg-config \
    && apt-get clean

WORKDIR /workspace
ENV CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
