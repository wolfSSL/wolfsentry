# wolfSentry CAN Bus Example

This example implements a simple echo client and server that uses TLS over a CAN bus using [ISO-TP](https://en.wikipedia.org/wiki/ISO_15765-2) as a transport protocol. This is because the raw CAN bus protocol can only support payloads of up to 8 bytes. The example requires Linux to run but can modified to work on any setup that uses CAN bus.

All packets received are filtered through wolfSentry and if the CAN bus addresses do not match the packet is filtered out.

## Building

You need to have wolfSSL installed on your computer prior to building, this will need to be built with `WOLFSSL_ISOTP` defined to provide ISO-TP functionality.

You will also need wolfSentry installed on your computer.

To generate the required SSL certificates use `./generate_ssl.sh`.

## Setting Up

If you do not have a physical CAN bus between too machines you can use the virtual CAN bus which is a Linux kernel module. This behaves just like a real CAN bus with a similar bandwidth. To enable this run the following commands:

```sh
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set vcan0 up
```

## Running

Both the client and server require three parameters:

1. The can bus address
2. The local address
3. The remote address

These addresses are used for ISP-TP's "Normal Fixed Addressing". For example, with a local of 11 and a remote of 22 the CAN arbitration is 0x18DA1122. wolfSentry is configured to require that both the local and remote addresses are correct.

On one console run the server, this should be executed first or the handshake will fail. This is executed using:

```sh
./server vcan0 11 22
```

Then in another terminal run the client:

```sh
./client vcan0 22 11
```

On both ends you will see:

```
SSL handshake done!
```

Once you see the message "SSL handshake done!" on both consoles you can enter text into the client console. When you hit "enter" this will be sent to the server via the TLS encrypted CAN bus and will echo there.

For example, on the client if we type "Hello world, this is a TLS test!":

```
Hello world! This is a CAN bus test!
Sending: Hello world! This is a CAN bus test!

Message sent
```

The server will echo:

```
Got message: Hello world! This is a CAN bus test!
```

If you very the addresses you will find that wolfSentry will block the messages before the application processes them.

## Cleaning Up

If you wish to disable the virtual CAN bus you can turn it off by doing:

```sh
sudo ip link set vcan0 down
```

