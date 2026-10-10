#!/usr/bin/python3

"""Minimal org.freedesktop.Notifications service for headless CI."""

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib


INTERFACE = "org.freedesktop.Notifications"
OBJECT_PATH = "/org/freedesktop/Notifications"


class NotificationService(dbus.service.Object):
    """Accept desktop notifications without requiring a graphical session."""

    @dbus.service.method(INTERFACE, in_signature="", out_signature="as")
    def GetCapabilities(self):
        return ["body"]

    @dbus.service.method(INTERFACE, in_signature="", out_signature="ssss")
    def GetServerInformation(self):
        return ("wolfSentry CI", "wolfSSL", "1.0", "1.2")

    @dbus.service.method(
        INTERFACE,
        in_signature="susssasa{sv}i",
        out_signature="u",
    )
    def Notify(
        self,
        app_name,
        replaces_id,
        app_icon,
        summary,
        body,
        actions,
        hints,
        expire_timeout,
    ):
        del app_name, replaces_id, app_icon, body, actions, hints, expire_timeout
        print(f"notification received: {summary}", flush=True)
        return dbus.UInt32(1)

    @dbus.service.method(INTERFACE, in_signature="u", out_signature="")
    def CloseNotification(self, notification_id):
        del notification_id


def main():
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    bus_name = dbus.service.BusName(INTERFACE, bus)
    service = NotificationService(bus_name, OBJECT_PATH)
    print("notification service ready", flush=True)
    main_loop = GLib.MainLoop()
    main_loop.run()
    del service


if __name__ == "__main__":
    main()
