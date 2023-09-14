# Notification Demos

* `log_server`: A TLS-enabled web server that reports wolfSentry logs.  See
  [`log_server/README.md`](log_server/README.md) for details.
* `udp_to_dbus`: A middleware daemon that accepts JSON notification packages
  over UDP from `log_server`, and generates DBUS notifications from them.  See
  [`udp_to_dbus/README.md`](udp_to_dbus/README.md) for details.

## Configuration

The IP interface used for notification can be set in `notify-config.json`,
in the `"user-values"` section:
* `udp_to_json` uses `"notification-listen-addr"` and `"notification-dest-port"` to receive inbound notifications from `log_server`.
* `log_server` listens for HTTPS connections to `"admin-listen-addr"` and
 `"admin-listen-port"`, and connects to `udp_to_json` at
 `"notification-server-addr"`, which will differ from
 `"notification-listen-addr"` if the latter is a wildcard address
 (e.g. `"0.0.0.0"`).

With the included `notify-config.json`, the notification bus runs over localhost
port 55555, and the `log_server` listens on all interfaces/addresses, including
public ones, at port 10443.
