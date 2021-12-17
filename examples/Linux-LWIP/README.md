# wolfSentry lwIP Echo Test

This is an extremely basic demo application that uses wolfSentry with the lwIP stack via PCAP on Docker to echo anything sent to it. wolfSentry will filter various types of traffic which can be tested using three Docker nodes the test generates.

## Prerequisites

This test is designed to be run on Linux or macOS, but should work on Windows as well. You need the following installed on your computer:

* Docker - <https://docs.docker.com/get-docker/>
* docker-compose - <https://docs.docker.com/compose/install/>

## Running echo server

The following command will build the test echo server and start this up along with three testing nodes:

```sh
sudo docker-compose -f docker-compose.yml up --build -d
```

You can follow the logs for the echo server using:

```sh
sudo docker-compose -f docker-compose.yml logs -f
```

It is recommended that you keep the logs following running whilst running the tests.

## Testing

### Accessing nodes

There are three user test nodes to play with. They are named `linux-lwip_tester?_1` where `?` is 1, 2 or 3. To log into tester2 as an example:

```sh
sudo docker exec -it linux-lwip_tester2_1 /bin/sh
```

### Node details

#### Echoserver

* IP address: 172.20.20.3 (node) 127.20.20.5 (echo process)
* MAC address: de:c0:de:01:02:03

The echo test process runs from this node, it uses PCAP and lwIP to create a static IP of 127.20.20.5 for the actually test.

#### Tester 1

* IP address: 172.20.20.10
* MAC address: de:c0:de:03:02:01

The sentry test is configured to allow this node to ping the echoserver node, but the TCP connection is not accepted during handshake.

#### Tester 2

* IP address: 172.20.20.20
* MAC address: de:c0:de:03:02:02

The sentry test is configured to block this node pinging the echoserver node, but the TCP connection is accepted during handshake.

#### Tester 3

* IP address: 172.20.20.30
* MAC address: de:c0:de:03:03:01

The sentry test is configured to deny traffic from this MAC address.

### Ping test

You can ping from any of the nodes using:

```sh
ping 127.20.20.5
```

Tester node 1 will work, tester 2 will be rejected for ICMP ping and tester 3 will be rejected for MAC address. This will be reflected in the logging output.

### Echo test

You can connect from any of the nodes using:

```sh
nc -v 172.20.20.5 11111
```

Tested node 2 will work and whatever you enter into the netcat terminal will be logged in the server log. Tester 1 will be rejected for the TCP connection and tester 3 will be rejected for MAC address.

## Shutting down

You can stop and clean up the nodes by running the following, this will also remove the virtual network:

```sh
sudo docker-compose -f docker-compose.yml down
```

## Notes

* The `lwip-include/arch` directory is a copy of the lwIP directory from `contrib/ports/unix/port/include/arch`.
