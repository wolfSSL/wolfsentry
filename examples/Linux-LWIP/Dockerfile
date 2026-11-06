FROM debian:12 AS builder

RUN echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential ca-certificates cmake git libpcap-dev netbase patch \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY . wolfsentry

RUN retry() { for attempt in 1 2 3; do "$@" && return 0; [ "$attempt" -lt 3 ] && sleep $((attempt * 15)); done; return 1; } \
    && retry git clone --depth 1 --branch STABLE-2_1_3_RELEASE \
        https://github.com/lwip-tcpip/lwip.git \
    && retry git clone --depth 1 --branch STABLE-2_1_0_RELEASE \
        https://git.savannah.nongnu.org/git/lwip/lwip-contrib.git \
        lwip/contrib \
    && cd lwip \
    && patch -p1 < ../wolfsentry/lwip/LWIP_PACKET_FILTER_API.patch

WORKDIR /src/wolfsentry

RUN make -j"$(nproc)" test && make install

RUN cp -a examples/Linux-LWIP /src/lwip-echo

WORKDIR /build

RUN cmake /src/lwip-echo/ && make -j"$(nproc)"

WORKDIR /app
RUN cp /build/lwip-runner .

COPY examples/Linux-LWIP/echo-config.json .

CMD /app/lwip-runner
