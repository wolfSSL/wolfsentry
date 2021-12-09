FROM debian:10 AS builder

RUN apt-get update && apt-get install -y unzip libpcap-dev build-essential git cmake libpcap0.8

WORKDIR /src

RUN git clone https://github.com/lwip-tcpip/lwip
RUN git clone https://github.com/wolfSSL/wolfsentry

WORKDIR wolfsentry

RUN CFLAGS="-g -O0" make -j && make install

WORKDIR /src

COPY . lwip-echo

WORKDIR /build

RUN cmake /src/lwip-echo/ && make -j

WORKDIR /app
RUN cp /build/lwip-runner .

COPY echo-config.json .

CMD /app/lwip-runner
