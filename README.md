madns
=====

madns (pronounced “madness”) is a DNS library written in Go for serving
abstract zone files as an authoritative nameserver.

An abstract zone file is any object implementing this interface:

  type Backend interface {
    Lookup(qname string) ([]dns.RR, error)
  }

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

Licence
-------
© 2014 Hugo Landau <hlandau@devever.net>    Licenced under the GPLv3 or later

