# Notification Demos

* `log_server`: A TLS-enabled web server that reports wolfSentry logs.  See
  [`log_server/README.md`](log_server/README.md) for details.
* `udp_to_dbus`: A middleware daemon that accepts JSON notification packages
  over UDP from `log_server`, and generates DBUS notifications from them.  See
  [`udp_to_dbus/README.md`](udp_to_dbus/README.md) for details.
