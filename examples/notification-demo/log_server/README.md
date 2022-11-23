# Access Controlled TLS Webserver Example

This is a demo application that starts a very basic HTTPS server. It is designed
to accept HTTPS connections on the address and port configured in the
"user-values" section of notify-config.json ("admin-listen-addr" and
"admin-listen-port"), and filter connections according to the policy defined by
rules in the "static-routes-insert" section of notify-config.json.

Connections are mutually authenticated, and the client must authenticate using a
certificate issued by one of the compiled-in certificate authorities.  Examples
demonstrating this using `curl` are below.

All connections are screened by wolfSentry, and for each connection, the peer
address and wolfSentry decision are logged in JSON format, and sent to the
`udp_to_dbus` notification server.

Two URLs are currently recognized: "/show-log", which dumps a history of
connections as a JSON array, and "/reset-log", which clears the log.

Role-based authorization is demonstrated, pivoting on the issuing authority for
the certificate presented by the client.  This access control is also
demonstrated in the `curl` examples below.

This example supports Linux or MacOSX, via `make` arguments (`TARGET=linux` or
`TARGET=macosx`), and defaults to Linux.

## Building the demo

1) Build wolfSentry

```
cd wolfsentry
make
make install
```

2) Build wolfSSL:

```
cd wolfssl
./configure --enable-wolfsentry --enable-opensslextra [--enable-intelasm]
make
make install
```

3) Build the `udp_to_dbus` notification daemon:

```
cd examples/notification-demo/udp_to_dbus
make
```

4) Build the `log_server` HTTPS server:

```
cd examples/notification-demo/log_server
make
```

## Running the demo

```sh
# start the echo server
./log_server

# or if using the notification daemon, optionally provide an alternate address for it, e.g.:
./log_server --kv-string notification-server-addr=10.0.4.4

# start the notification daemon in another terminal (see examples/notification-demo/udp_to_dbus)
# (change working directory to examples/notification-demo/udp_to_dbus)
./udp_to_dbus

# For the below client invocations, change working directory to examples/notification-demo/log_server.

# Note these examples assume a modern curl.  If necessary, build and install it -- see https://curl.se/

# Connect from `curl` and dump the logs
curl --cert ./certs/client-ecc384-cert.pem --key ./certs/client-ecc384-key.pem --cacert ./certs/ca-ecc-cert.pem --resolve www.wolfssl.com:10443:127.0.0.1 https://www.wolfssl.com:10443/show-log

# Connect from `curl` and reset the logs
curl --cert ./certs/client-ecc384-cert.pem --key ./certs/client-ecc384-key.pem --cacert ./certs/ca-ecc-cert.pem --resolve www.wolfssl.com:10443:127.0.0.1 https://www.wolfssl.com:10443/reset-log

# Failed mutual auth example -- self-signed client cert:
curl --cert ./certs/client-cert-ext.pem --key ./certs/client-key.pem --cacert ./certs/ca-ecc-cert.pem --resolve www.wolfssl.com:10443:127.0.0.1 https://www.wolfssl.com:10443/show-log

# Failed mutual auth example -- valid issuer but invalid use -- "Ext Key Use server/client auth not set":
curl --cert ./certs/server-ecc384-cert.pem --key ./certs/server-ecc384-key.pem --cacert ./certs/ca-ecc-cert.pem --resolve www.wolfssl.com:10443:127.0.0.1 https://www.wolfssl.com:10443/show-log

# Connect from `curl` and show logs with readonly authorization:
curl --cert ./certs/server-cert.pem --key ./certs/server-key.pem --cacert ./certs/ca-ecc-cert.pem --resolve www.wolfssl.com:10443:127.0.0.1 https://www.wolfssl.com:10443/show-log

# Use a different valid cert issued by the readonly CA to connect from `curl` and show logs:
curl --cert ./certs/entity-no-ca-bool-cert.pem --key ./certs/entity-no-ca-bool-key.pem --cacert ./certs/ca-ecc-cert.pem --resolve www.wolfssl.com:10443:127.0.0.1 https://www.wolfssl.com:10443/show-log

# Role-based authorization failure example
curl --cert ./certs/server-cert.pem --key ./certs/server-key.pem --cacert ./certs/ca-ecc-cert.pem --resolve www.wolfssl.com:10443:127.0.0.1 https://www.wolfssl.com:10443/reset-log
```
