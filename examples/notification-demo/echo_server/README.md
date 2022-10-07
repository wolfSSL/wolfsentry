# wolfSentry Linux LWIP wolfSSL Example

This is a demo application that starts a very basic HTTPS server. It is designed to accept HTTPS connections on port 8080 from a specific IP. Connections from other IPs will be blocked.

All wolfSentry accept or reject actions are logged in JSON format and sent to udp_to_dbus notification server. An accepted connection will get the logs returned.

This example supports Linux `BUILD_FOR_LINUX` or LWIP `BUILD_FOR_FREERTOS_LWIP`.

## Building the demo

1) Build wolfSentry

```
cd wolfsentry
make
make install
```

2) Build wolfSSL

```
cd wolfssl
./configure --enable-wolfsentry --enable-opensslextra [--enable-intelasm]
make
make install
```

3) Build udp_to_dbus notification example

```
cd examples/notification-demo/udp_to_dbus
make
```

4) Build this echo server example

```
cd examples/notification-demo/echo_server
make
```

## Running the demo

```sh
# start the echo server
./echo_server

# if using the notification server then provide the address of it
./echo_server --kv-string notification-dest-addr=10.0.4.4

# start the notification server (see examples/notification-demo/udp_to_dbus)
./udp_to_dbus



# from wolfSSL start a TLS client connection
 ./examples/client/client -v 4 -c ./certs/client-ecc384-cert.pem -k ./certs/client-ecc384-key.pem -A ./certs/ca-ecc-cert.pem

# from CURL with show-log
curl --cert ./certs/client-ecc384-cert.pem --key ./certs/client-ecc384-key.pem --cacert ./certs/ca-ecc-cert.pem --resolve www.wolfssl.com:10443:127.0.0.1 https://www.wolfssl.com:10443/show-log

# Failed mutual auth example
curl --cert ./certs/entity-no-ca-bool-cert.pem --key ./certs/entity-no-ca-bool-key.pem --cacert ./certs/ca-ecc-cert.pem --resolve www.wolfssl.com:10443:127.0.0.1 https://www.wolfssl.com:10443/show-log
```
