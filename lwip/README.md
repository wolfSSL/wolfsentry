This directory contains a jumbo patch that adds the `LWIP_PACKET_FILTER_API`,
a generic packet/event filter callback facility.

The patch can be applied to the most recent full release of lwIP (v2.1.3), or
any newer version from the lwIP git repository, and was developed with commit
3fe8d2fc43 (Jan 3 2023) as the base.  The patch adds no external dependencies,
so it will work in any existing lwIP project with a sufficiently recent base
version.

Two versions of the patch are included, `LWIP_PACKET_FILTER_API.patch` for use
with Linux-like setups and git sources (lines terminated with LF), and
`LWIP_PACKET_FILTER_API.CRLF.patch` for CRLF setups and zip sources.  They
differ only in line termination.  To patch the lwIP release zip sources, use
`LWIP_PACKET_FILTER_API.CRLF.patch`, and on Linux, use `patch -p1 --binary`.  To
patch git sources, use `LWIP_PACKET_FILTER_API.patch` and `patch -p1`.

To build the filter facility into the generated objects, add
```
#define LWIP_PACKET_FILTER_API 1
```
to `lwipopts.h`.

The patch does not add any new `.c` files, so the only required project change
is to `lwipopts.h`.

Building the filter facility into lwIP does not in itself make lwIP behave
differently in any way, and involves negligible overhead.  To activate and use
the facility, the layer- and protocol-specific callback installation routines
are called, as they are by the wolfSentry routines in
`src/lwip/packet_filter_glue.c`.

The installation routines are of the form

```
void tcp_filter(tcp_filter_fn cb);
void tcp_filter_mask(packet_filter_event_mask_t mask);
void tcp_filter_arg(void *arg);
```

Possible values in place of `tcp` are `ethernet`, `ip4`, `ip6`, `icmp`, `icmp6`,
and `udp`.

`packet_filter_event_mask_t`, `packet_filter_event_t`, and `struct
packet_filter_event`, are defined in the new header
`src/include/lwip/filter.h`.  The argument structure of the callback routines is
layer-/protocol-specific, and is defined in the respective lwIP header files,
gated on `LWIP_PACKET_FILTER_API`.  E.g., the prototypes for the `tcp` routines
are in `src/include/lwip/tcp.h`.

See `src/lwip/packet_filter_glue.c` for comprehensive examples of usage.
