madns
=====

[![godocs.io](https://godocs.io/gopkg.in/hlandau/madns.v2?status.svg)](https://godocs.io/gopkg.in/hlandau/madns.v2) [![Build status](https://github.com/hlandau/madns/actions/workflows/go.yml/badge.svg)](#) [![No modules](https://www.devever.net/~hl/f/no-modules2.svg) 100% modules-free.](https://www.devever.net/~hl/gomod)

madns (pronounced “madness”) is a DNS library written in Go for serving
abstract zone files as an authoritative nameserver.

An abstract zone file is any object implementing this interface:

```go
  type Backend interface {
    Lookup(qname, streamIsolationID string) ([]dns.RR, error)
  }
```

Import as `gopkg.in/hlandau/madns.v2`.

Why
---
Zone files are easy to understand. They contain lists of records, each with an
owner name, type, and type-specific data (as well as class and TTL).

However, DNS is more complicated than meets the eye. There are a series of
complicated rules governing how zone file data is served. Thus, serving zones
isn't as simple as just spitting out the matching records in response to
queries.

madns aims to implement the glue between the DNS wire protocol (implemented in
Go by `miekg/dns`) and an abstract zone file. It is similar in this regard to
PowerDNS's pipe backend, and intentionally so.

The abstract zone interface doesn't include a 'qtype' parameter as in many
cases this would mean calls would have to be repeated to check for the
existence of e.g. CNAMEs. Since most owner names won't have a very large number
of records, this shouldn't be a problem (unless, I suppose, you have some sort
of application where returning records of a particular type is a lot more
computationally expensive, and they can't be moved to another owner name).

Of course madns only serves records corresponding to a client's request,
qtype-wise and otherwise.

Since madns is implemented as a library it can be easily embedded into a larger
daemon.

Details
-------
madns builds on `miekg/dns`. It aims to offer a high-level interface on top of
the low level interface it provides.

madns supports DNSSEC and uses “NSEC3 white lies” (NSEC3NARROW in PowerDNS
terminology).

Stream Isolation
----------------
Abstract zone files accept a `streamIsolationID` argument.  Your abstract zone
file must process the stream isolation ID according to the following rules:

1. If your abstract zone file's `Lookup` implementation generates no public
   network traffic, then you can ignore the stream isolation ID.
1. If your abstract zone file's implementation generates public network traffic
   over the Tor network (or a similar anonymity network), then your abstract
   zone file must make sure that two `Lookup` calls that have unequal stream
   isolation ID's do not produce public network traffic over the same Tor
   circuit (or equivalent for other anonymity networks).  Typically you would
   do this via the SOCKS5 username field.
1. If your abstract zone file's implementation saves any state between
   different `Lookup` calls (e.g. caching), then your abstract zone file must
   make sure that two `Lookup` calls that have unequal stream isolation ID's do
   not share any such state.
1. If your abstract zone file is unable to provide the above guarantees or
   produces public network traffic that is not routed over Tor (or a similar
   anonymity network), then your abstract zone file must return an error
   (without producing network traffic) if the stream isolation ID is unequal to
   the empty string.

DNS clients who wish to specify a stream isolation ID can do so via the EDNS0
option code `65312`, which is within the "Local/Experimental Use" range as per
RFC 6891.

Licence
-------

    © 2014 Hugo Landau <hlandau@devever.net>    Licenced under the GPLv3 or later

