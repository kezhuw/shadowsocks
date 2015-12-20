# Shadowsocks
Shadowsocks implementation written in Go.

## What it is?
Yet another [shadowsocks](https://github.com/shadowsocks/shadowsocks/) implementation.
Not official, but conforms to its [protocol](https://shadowsocks.org/en/spec/protocol.html).

## What it is not?
It is not a [socks5](https://tools.ietf.org/rfc/rfc1928.txt) implementation.
Though, it does contain a package [socks5](socks5/socks5.go) to read and write socks5 messages.

## Why not another name?
Should I named it [yassi](https://en.wikipedia.org/wiki/Yet_another)?

## What is missing?
Various cipher methods and UDP are not supported. For now, only supported cipher methods are:

-   aes-128-cfb
-   aes-192-cfb
-   aes-256-cfb
-   rc4-md5

## Usage
```
Usage of shadowsocks:
  -config string
        Configuration file
  -help
        Print usage
```
See [examples/config.toml](examples/config.toml) for configration fields.

## Details
Go godoc to see [documentation](https://godoc.org/github.com/kezhuw/shadowsocks).

Use `git submodule` and [vendor](https://docs.google.com/document/d/1Bz5-UB7g2uPBdOx-rw5t9MxJwkfpx90cqG9AFL0JAYo/) to resolve dependency.
So if you want to build it, Go 1.5 is preferred.

It is worth mentioning that cipher methods are supported via driver-like
method used by official [database/sql](https://golang.org/pkg/database/sql/#Register) package.
So it should be trivially easy to integrate external cipher method if you contribute one.
See file [crypto.go](crypto/crypto.go), [crypto/aes.go](crypto/aes/aes.go),
[cmd/shadowsocks/ciphers.go](cmd/shadowsocks/ciphers.go) for details.

## License 
Released under The MIT License (MIT). See [LICENSE](LICENSE) for the full license text.

## Links
Some implementations that I read portions of them:

-   [Shadowsocks](https://github.com/shadowsocks-backup/shadowsocks) Official implementation, written in Python. Official repository is purged,
    here is a backup.
-   [shadowsocks-go](https://github.com/shadowsocks/shadowsocks-go) One of yet another implementations, written in Go.

## Contributions
Due to permissive license, feel free to fork and hack.
If you have any questions, fire issues. For bugs and features, pull requests are preferred.

## TODO
Wait a minute. I need to drink some wine.
