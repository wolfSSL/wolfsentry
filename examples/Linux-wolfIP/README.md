# Linux wolfIP + wolfSentry Demo

This example runs a single wolfIP instance on a TAP interface and forwards
wolfIP packet-filter events into wolfSentry via the wolfIP glue layer.  The
installed wolfSentry actions log every inbound Ethernet frame and drop every
seventh inbound ICMP echo request while logging the drop decision.

## Prerequisites

* Linux host with `/dev/net/tun` access (run the demo with `sudo`).
* `libpcap` is **not** required.
* Build `wolfsentry` with wolfIP support enabled so the packet-filter glue is
  present:

  ```sh
  cd ../../wolfsentry
  make WOLFIP=1 WOLFIP_CONFIG_DIR=examples/Linux-wolfIP/wolfip
  ```

  The example will then compile its own copy of wolfIP from `$(WOLFIP_PATH)`
  using the local configuration in `wolfip/config.h`, so you do not need to
  build wolfIP separately.  Edit that file if you need different Ethernet/TAP
  settings, such as the wolfIP and host IP addresses or the TAP interface name.

## Build the demo

```sh
cd wolfsentry/examples/Linux-wolfIP
make            # override WOLFIP_PATH=/path/to/wolfip if needed
```

The Makefile first builds a local `libwolfip.a` from
`$(WOLFIP_PATH)/src/wolfip.c`, picking up the Ethernet/TAP configuration in
`wolfip/config.h`, and then links the demo against that static library plus
`../../../wolfsentry/libwolfsentry.a`.  Override `WOLFIP_PATH` if your source
tree lives elsewhere.  If `libwolfsentry.a` is missing or older than the
example sources, the Makefile automatically runs
`make WOLFIP=1 WOLFIP_CONFIG_DIR=examples/Linux-wolfIP/wolfip` inside
`../../wolfsentry` so the packet-filter glue is rebuilt with the local config.

## Run the demo

```sh
sudo ./wolfip-wolfsentry-demo
```

The program:

1. Initializes wolfSentry, registers two actions (`log-event` and
   `icmp-mod7`), and loads `wolfip-config.json`.
2. Installs wolfSentry as the wolfIP packet filter for Ethernet, IPv4 and
   ICMP events.
3. Brings up wolfIP on a TAP interface (default host IP `10.10.10.1`,
   wolfIP address `10.10.10.2`) and enters the polling loop.

While it runs you can exercise it from the host by pinging
`10.10.10.2`.  The demo now starts a background
`ping -I wolfip0 -c 100 10.10.10.2` process automatically so you immediately
get traffic; it stops after 100 packets, and you can launch your own ping if
you prefer.  ICMP echo requests are accepted except when the running counter is
a multiple of 7 – only those discarded packets are logged.

The demo links in wolfIP's POSIX TAP driver (`tap_linux.c`), so the call to
`tap_init()` inside the sample automatically creates, configures, and brings up
the TAP interface on the host (default name `wolfip0`).  No manual `ip`
commands are required beyond running the binary with sufficient privileges.

Stop the demo with `Ctrl+C`.

## Cleaning up

```sh
make clean
```

This removes the local binary and object files; it does not touch the
wolfIP/wolfSentry build outputs.
