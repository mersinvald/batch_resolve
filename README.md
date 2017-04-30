[![Build Status](https://travis-ci.org/mersinvald/batch_resolve.svg?branch=master)](https://travis-ci.org/mersinvald/batch_resolve)
[![Crates.io](https://img.shields.io/crates/v/batch_resolve_cli.svg)](https://crates.io/crates/batch_resolve_cli)
[![Gitter](https://img.shields.io/badge/GITTER-join%20chat-green.svg)](https://gitter.im/batch_resolve/Lobby?utm_source=share-link&utm_medium=link&utm_campaign=share-link)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/mersinvald)

This page in [Russian](README_RUS.md)

# Batch Resolve

Fast asynchronous DNS resolver

## Install
### Distro packages
There are prebuilt *deb* and *rpm* packages for x86_64 you can find within the releases in [the list of versions](https://github.com/mersinvald/batch_resolve/tags)

Arch Linux users can install the package [from AUR](https://aur.archlinux.org/packages/batch_resolve/)

### Static binary
Every release binary can be found in the [the list of versions](https://github.com/mersinvald/batch_resolve/tags). Just place it to one of directories in your PATH (e.g. /usr/bin)

### Install from crates.io
If you have rust toolkit installed, you can install *batch_resolve* with
```
cargo install batch_resolve_cli
```

## Usage

Input and output format is list delimited with new line.
Consider such input `domains.txt`
```
google.com
rust-lang.org
mozilla.org
```

Resolve all `A` records:
```
batch_resolve --in domains.txt --out hosts.txt --query A
```

Resolve `A` and `AAAA` records:
```
batch_resolve -i domains.txt -o hosts.txt -q A
              -i domains.txt -o hosts.txt -q AAAA  
```

### Configuration
By default batch_resolve uses Google DNS servers `8.8.8.8` and `8.8.4.4` and retries `10` times on Connection Timeout error.
These and Queries Per Second parameters may be altered in configuration file.

Configuration file may be placed in the following locations (priority descending):
```
batch_resolve.toml
$HOME/.config/batch_resolve.toml
/etc/batch_resolve.toml
```

Configuration includes DNS servers, queries per second amount and retries on failure count
```toml
# DNS servers are only accepted as socket addresses
# If port is not specified default DNS :53 port will be used
dns = [
    "8.8.8.8"
]

# How many queries to perform per second
queries_per_second = 2000

# Times to retry on connection timeout
retry = 5
```

Configuration template can also be found [here](batch_resolve.toml)

## Contributing

To build project please clone the repo
```
git clone git@github.com:mersinvald/batch_resolve.git
```
And run `cagro build`
```
cd batch_resolve
cargo build
```
`batch_resolve` can be build with stable rust

Please file an issue if you have any improvement suggestion or bug report.

Pull Requests are welcome also!

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgement
* [TRust-DNS: A Rust based DNS client and server, built to be safe and secure from the ground up](https://github.com/bluejekyll/trust-dns)
* [rust-musl-builder: Docker container for easily building static Rust binaries](https://github.com/emk/rust-musl-builder)gi

## Donate

If you feel that this work is worth something and that it saved your time you can give me a cup of coffee :)

* [Donate with PayPal](https://www.paypal.me/mersinvald)
* [Donate with yandex.money](http://yasobe.ru/na/batch_resolve_coffee)