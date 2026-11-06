FROM ubuntu:26.04@sha256:157dc3d6e4a3e4f2c68d12df9df9ed6e808b59af6d4c3757b432b4f519916725

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        ca-certificates \
        clang \
        clang-tidy \
        cppcheck \
        curl \
        doxygen \
        dwarves \
        gcc \
        gcc-15 \
        gcc-15-multilib \
        gcc-arm-none-eabi \
        gcc-multilib \
        git \
        graphviz \
        libnewlib-arm-none-eabi \
        libclang-rt-21-dev \
        libnotify-dev \
        libtool \
        llvm \
        make \
        patch \
        qemu-user \
        texlive-fonts-recommended \
        texlive-latex-base \
        texlive-latex-extra \
        texlive-latex-recommended \
        texlive-plain-generic \
        util-linux \
        valgrind \
        xz-utils \
        zip \
    && rm -rf /var/lib/apt/lists/*

ARG ARMEB_TOOLCHAIN=armebv7-eabihf--glibc--stable-2026.08-1
ARG ARMEB_TOOLCHAIN_SHA256=4d93a7b26c0909ea7574e98246522cf6b77491d43a7ca7aa08ae1c29ecf07b0d

# Buildroot's compiler wrapper finds its real binary from argv[0], so expose the
# armeb-linux-gnueabihf names as exec shims, and put the sanitizer runtimes in the sysroot qemu loads from.
RUN curl -fsSL --retry 3 -o /tmp/armeb.tar.xz \
        "https://toolchains.bootlin.com/downloads/releases/toolchains/armebv7-eabihf/tarballs/${ARMEB_TOOLCHAIN}.tar.xz" \
    && echo "${ARMEB_TOOLCHAIN_SHA256}  /tmp/armeb.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/armeb.tar.xz -C /opt \
    && rm /tmp/armeb.tar.xz \
    && tc="/opt/${ARMEB_TOOLCHAIN}" \
    && target="${tc}/armeb-buildroot-linux-gnueabihf" \
    && for f in "${tc}"/bin/armeb-buildroot-linux-gnueabihf-*; do \
           case "$f" in *.br_real) continue ;; esac; \
           shim="/usr/local/bin/$(basename "$f" | sed 's/^armeb-buildroot-/armeb-/')"; \
           printf '#!/bin/sh\nexec %s "$@"\n' "$f" > "$shim"; \
           chmod +x "$shim"; \
       done \
    && cp -a "${target}"/lib/libasan.so* "${target}"/lib/libubsan.so* "${target}"/lib/libatomic.so* "${target}/sysroot/lib/" \
    && ln -s "${target}/sysroot" /usr/armeb-linux-gnueabihf
