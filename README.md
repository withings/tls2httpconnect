# tls2httpconnect

This tool is meant to run between a NAT rule intercepting HTTPS
traffic and an HTTP CONNECT proxy.

It listens for TCP connections (sent by NAT) and waits for the
ClientHello message to appear. The SNI is then extracted and a
corresponding HTTP CONNECT request is sent to the upstream
proxy. tls2httpconnect and the proxy then act together as simple TCP
relays between the client and the remote endpoint.

This essentially allows for transparent HTTPS proxying on routers. For
an all-in-one solution, you can also find similar functionality in
Squid (SslBump) and Apache Traffic Server.


## Installing

tls2httpconnect can be built using cargo:

    $ cargo build --release

You can then install it as you please, for instance using `install`:

    $ sudo install -m 0755 target/release/tls2httpconnect /usr/local/bin


## Usage

For quick usage instructions, run `tls2httpconnect -h`.

When running on the router performing NAT, a typical rule would be:

    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8888

This effectively captures all incoming traffic to TCP 443 and
redirects it to local port 8888, where tls2httpconnect is waiting.


## License

tls2httpconnect is released under the terms of the AGPL.
