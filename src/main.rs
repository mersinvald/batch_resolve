#[macro_use]
extern crate futures;
extern crate futures_cpupool;
extern crate trust_dns;
extern crate tokio_core;

mod error;
mod resolver;

use std::borrow::Cow;
use std::iter::IntoIterator;
use std::iter::Iterator;
use std::collections::HashSet;
use std::path::Path;
use std::io::{self, Read, Write};
use std::fs::File;

use tokio_core::reactor::{Core, Handle};

use futures::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use std::rc::Rc;
use futures::future::Future;
use futures::Sink;
use futures::Stream;
use futures::future::{poll_fn, lazy};
use futures::Async;

use error::*;
use resolver::*;

fn resolve<'a, F>(loop_handle: Handle, tx: mpsc::Sender<String>, input: HashSet<String>, mut resolve_fn: F) 
    where F: FnMut(&str) -> Box<Future<Item=Vec<String>, Error=ResolverError>>

{
    for item in input.iter() {
        let tx = tx.clone();
        loop_handle.spawn(
            resolve_fn(&item).and_then(|results| {
                for result in results.into_iter() {
                    // use of moved value: `tx`
                    // value moved here in previous iteration of loop
                    tx.send(result);
                }   
                Ok(())
            }).map_err(|_| ())
        );    
    }
}

fn receive(loop_handle: Handle, rx: mpsc::Receiver<String>, original: HashSet<String>, filename: String) {
    loop_handle.spawn(
        rx.for_each(move |item| {
            // cannot borrow captured outer variable in an `FnMut` closure as mutable
            original.insert(item);
            Ok(())
        }).and_then(|_| {
            // capture of moved value: `original`
            // value captured here after move
            write_file(original, filename);
            Ok(())
        })
    )
}

fn main() {
    // Synchronously load files
    let (mut domains, mut ips) = (
        load_file("data/domains.txt").unwrap(),
        load_file("data/hosts.txt").unwrap()
    );

    // Create Tokio Core
    let mut lp = Core::new().unwrap();
    let handle = lp.handle();

    // Create mpsc channels to get results from tasks
    let (domains_tx, domains_rx) = mpsc::channel(1024);
    let (ips_tx, ips_rx) = mpsc::channel(1024);
        
        
    // Create resolvers with different DNS servers
    let mut resolver1 = TrustDNSResolver::new("8.8.8.8".parse().unwrap(), handle.clone());
    let mut resolver2 = TrustDNSResolver::new("8.8.4.4".parse().unwrap(), handle.clone());

    // Spawn async receivers, move cloned data there
    receive(handle.clone(), domains_rx, domains.clone(), String::from("data/domains.out"));
    receive(handle.clone(), ips_rx,     ips.clone(),     String::from("data/hosts.out"));
       
    // Spawn resolvers and move loaded data there
    resolve(handle.clone(), domains_tx, ips,     |item| resolver1.reverse_resolve(item));
    resolve(handle.clone(), ips_tx,     domains, |item| resolver2.resolve(item));
    
    lp.run(/* What do I pass here if I spawned every task with handle? */);

    // How can I get back my HasSet I moved to receivers?
}

fn load_file<P: AsRef<Path>>(path: P) -> io::Result<HashSet<String>> {
    let mut buffer = String::new();
    let mut file = File::open(path)?;
    file.read_to_string(&mut buffer)?;
    Ok(buffer.lines().map(String::from).collect())
}

fn write_file<'a, I: IntoIterator<Item=String>, P: AsRef<Path>>(data: I, path: P) -> io::Result<()> {
    let mut file = File::create(path)?;
    let mut data = data.into_iter().collect::<Vec<_>>();
    data.sort();
    for item in &data {
        file.write(item.as_bytes())?;
        file.write(b"\n")?;
    }
    Ok(())
}
