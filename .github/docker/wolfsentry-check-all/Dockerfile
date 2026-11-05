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
        texlive-fonts-recommended \
        texlive-latex-base \
        texlive-latex-extra \
        texlive-latex-recommended \
        texlive-plain-generic \
        util-linux \
        valgrind \
        zip \
    && rm -rf /var/lib/apt/lists/*
