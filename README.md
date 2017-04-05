[![Build Status](https://travis-ci.org/mersinvald/batch_resolve.svg?branch=master)](https://travis-ci.org/mersinvald/batch_resolve)
[![Crates.io](https://img.shields.io/crates/v/batch_resolve_cli.svg)](https://crates.io/crates/batch_resolve_cli)
[![Gitter](https://img.shields.io/badge/GITTER-join%20chat-green.svg)](https://gitter.im/batch_resolve/Lobby?utm_source=share-link&utm_medium=link&utm_campaign=share-link)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/mersinvald)

# Batch Resolve

Fast asynchronous DNS resolver

## Installing
### Static binary
Every release binary can be found in the [the list of versions](https://github.com/mersinvald/batch_resolve/tags). Place it to your binary folder and proceed to usage.


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

Configuration includes DNS servers with their QPS properties and retries on failure count
```toml
[[dns]]
addr = "8.8.8.8:53" # Google primary DNS
qps  = 1000         # How much queries per second will be performed on this DNS

# If port is not specified default DNS :53 port will be used
[[dns]]
addr = "8.8.4.4"    # Google secondary DNS
qps  = 500

# Times to retry on connection timeout
retry = 10
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

## Donate

If you feel that this work is worth something and that it saved your time you can give me a cup of coffee :)

* [Donate with PayPal](https://www.paypal.me/mersinvald)
* [Donate with yandex.money](http://yasobe.ru/na/batch_resolve_coffee)