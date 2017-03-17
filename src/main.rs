#[macro_use]
extern crate error_chain;
extern crate nix;
extern crate threadpool;
extern crate futures;
extern crate futures_cpupool;
extern crate trust_dns;
extern crate tokio_core;

mod resolver_sys;
mod resolver;

use std::borrow::Cow;
use std::iter::IntoIterator;
use std::iter::Iterator;
use std::collections::HashSet;
use std::path::Path;
use std::io::{self, Read, Write};
use std::fs::File;

use futures::future;
use future::Future;

use resolver::*;

fn main() {
    let (mut hostname_buffer, mut ip_buffer) = (
        String::new(),
        String::new()
    );

    let (mut hostnames, mut ips) = (
        load_file(&mut hostname_buffer, "data/domains.txt").unwrap(),
        load_file(&mut ip_buffer, "data/hosts.txt").unwrap()
    );

    let resolver = CpuPoolResolver::new(4);

    println!("Resolving hostname -> ip");

    let resolved_ips = future::join_all(
        hostnames.iter().map(|hostname| resolver.resolve(hostname))
    ).wait().unwrap();

    println!("Resolving ip -> hostname");

    let resolved_hostnames = future::join_all(
        ips.iter().map(|ip| resolver.reverse_resolve(ip.parse().unwrap()))
    ).wait().unwrap();

    println!("Done. Saving results");

    for ip in resolved_ips.into_iter()
                          .filter(Option::is_some)
                          .map(Option::unwrap)
                          .flat_map(|i|i)
                          .map(|ip| format!("{}", ip)) 
    {
        ips.insert(Cow::from(ip));
    }

    for hostname in resolved_hostnames.into_iter()
                                      .filter(Option::is_some)
                                      .map(Option::unwrap)
    {
        hostnames.insert(Cow::from(hostname));
    }

    write_file(ips.iter(), "data/hosts.out").unwrap();
    write_file(hostnames.iter(), "data/hostnames.out").unwrap();
}

fn load_file<'a, P: AsRef<Path>>(buffer: &'a mut String, path: P) -> io::Result<HashSet<Cow<'a, str>>> {
    let mut file = File::open(path)?;
    file.read_to_string(buffer)?;
    Ok(buffer.lines().map(Cow::from).collect())
}

fn write_file<'a, I: IntoIterator<Item=&'a Cow<'a, str>>, P: AsRef<Path>>(data: I, path: P) -> io::Result<()> {
    let mut file = File::create(path)?;
    let mut data = data.into_iter().collect::<Vec<_>>();
    data.sort();
    for item in &data {
        file.write(item.as_bytes())?;
        file.write(b"\n")?;
    }
    Ok(())
}
