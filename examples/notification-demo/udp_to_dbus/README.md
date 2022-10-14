# UDP to DBUS Notification example

This is a demonstration application daemon that relays wolfSentry notifications,
received from the `log_server`, to the desktop DBUS facility, according to the
configuration in `../notify-config.json`.

For more information, see [`../log_server/README.md`](../log_server/README.md).

## Building the demo

1) Build wolfSentry

```
cd wolfsentry
make
make install
```

2) Build `udp_to_dbus`:

```
make
```

## Run the demo:

```sh
./udp_to_dbus
```
