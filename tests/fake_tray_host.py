#!/usr/bin/env python3
"""A stand-in tray host for tests: owns org.kde.StatusNotifierWatcher, and for
each item that registers prints its icon, status and menu labels as JSON lines.

    fake_tray_host.py [--click LABEL]   (clicks that menu item once it appears)
"""

import json
import sys

from gi.repository import Gio, GLib

XML = """<node><interface name="org.kde.StatusNotifierWatcher">
  <method name="RegisterStatusNotifierItem"><arg type="s" name="service" direction="in"/></method>
  <property name="IsStatusNotifierHostRegistered" type="b" access="read"/>
  <property name="ProtocolVersion" type="i" access="read"/>
  <property name="RegisteredStatusNotifierItems" type="as" access="read"/>
</interface></node>"""
click = sys.argv[sys.argv.index("--click") + 1] if "--click" in sys.argv else None
items = []


def report(conn, service):
    def prop(name):
        reply = conn.call_sync(service, "/StatusNotifierItem", "org.freedesktop.DBus.Properties", "Get",
                               GLib.Variant("(ss)", ("org.kde.StatusNotifierItem", name)), None,
                               Gio.DBusCallFlags.NONE, -1, None)
        return reply.unpack()[0]
    menu = prop("Menu")
    _rev, (_id, _props, children) = conn.call_sync(service, menu, "com.canonical.dbusmenu", "GetLayout",
                                                   GLib.Variant("(iias)", (0, -1, [])), None,
                                                   Gio.DBusCallFlags.NONE, -1, None).unpack()
    labels = [(c[0], c[1].get("label", "---")) for c in children]
    print(json.dumps({"service": service, "icon": prop("IconName"), "status": prop("Status"),
                      "tooltip": prop("ToolTip")[3], "pixmaps": len(prop("IconPixmap")),
                      "menu": [label for _, label in labels]}), flush=True)
    global click
    for item_id, label in labels:
        if click and label == click:
            conn.call_sync(service, menu, "com.canonical.dbusmenu", "Event",
                           GLib.Variant("(isvu)", (item_id, "clicked", GLib.Variant("s", ""), 0)), None,
                           Gio.DBusCallFlags.NONE, -1, None)
            print(json.dumps({"clicked": label}), flush=True)
            click = None
    return False


def call(conn, sender, path, iface, method, params, invocation):
    service = params.unpack()[0]
    items.append(service if service.startswith(":") or "." in service else sender)
    invocation.return_value(None)
    GLib.timeout_add(500, report, conn, items[-1])
    GLib.timeout_add_seconds(2, report, conn, items[-1])


def changed(conn, sender, _path, _iface, _signal, _params):
    GLib.timeout_add(100, report, conn, sender)


def acquired(conn, _name):
    for signal in ("NewIcon", "NewStatus", "NewToolTip"):
        conn.signal_subscribe(None, "org.kde.StatusNotifierItem", signal, "/StatusNotifierItem", None,
                              Gio.DBusSignalFlags.NONE, changed)
    conn.register_object("/StatusNotifierWatcher", Gio.DBusNodeInfo.new_for_xml(XML).interfaces[0], call,
                         lambda *a: GLib.Variant("b", True) if a[4] == "IsStatusNotifierHostRegistered" else None, None)


Gio.bus_own_name(Gio.BusType.SESSION, "org.kde.StatusNotifierWatcher", Gio.BusNameOwnerFlags.NONE,
                 acquired, None, lambda *_: sys.exit("can't own org.kde.StatusNotifierWatcher"))
GLib.MainLoop().run()
