FROM ghcr.io/wolfssl/wolfcose-ci@sha256:c073c7afb4cd3f296b8c1a305db2f718530b7a8aca899482629aee3a5cf8bfbc

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bubblewrap \
        dbus \
        gcc-arm-none-eabi \
        iproute2 \
        iputils-ping \
        libnewlib-arm-none-eabi \
        libnotify-dev \
        python3-dbus \
        python3-gi \
    && rm -rf /var/lib/apt/lists/*
