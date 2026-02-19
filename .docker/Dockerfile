ARG BASE_IMAGE=slim-trixie

FROM rust:${BASE_IMAGE} AS builder

ARG DEBIAN_FRONTEND=noninteractive

# install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    cmake \
    gcc \
    libc6-dev \
    make

# build project
COPY . /source
WORKDIR /source

RUN cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_TESTING=OFF -S . -B build
RUN cmake --build build
RUN DESTDIR=/install cmake --install build

FROM busybox:stable

COPY --from=builder /install/ /install/
