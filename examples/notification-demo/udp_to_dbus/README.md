# UDP to DBUS Notification example

This is a demonstration application daemon uses `../../tests/test-config.json` to show wolfSentry notifications with the `echo_server`.

## Building the demo

1) Build wolfSentry

```
cd wolfsentry
make
make install
```

2) Build udp_to_dbus

```
make
```

## Testing the demo

```sh
# Supply the IP address on the interface to listen to notifications
./udp_to_dbus --kv-string notification-dest-addr=[IPADDR]
```
