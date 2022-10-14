# Notification Demos

* `log_server`: A TLS-enabled web server that reports wolfSentry logs.  See
  [`log_server/README.md`](log_server/README.md) for details.
* `udp_to_dbus`: A middleware daemon that accepts JSON notification packages
  over UDP from `log_server`, and generates DBUS notifications from them.  See
  [`udp_to_dbus/README.md`](udp_to_dbus/README.md) for details.

## Configuration

The IP interface used for notification can be changed in the `notify-config.json` using:
* `udp_to_json` uses `notification-listen-addr`
* `log_server` uses `notification-server-addr`

To sync the .json to .h run `json_to_c.sh`.
