#![feature(conservative_impl_trait)]
#![feature(box_syntax)]

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
use futures::stream;
use std::iter;
use std::env;
use std::io::stdout;

use error::*;
use resolver::*;

fn resolve<F>(input: HashSet<String>, mut resolve_fn: F) 
    -> Box<Stream<Item=Option<Vec<DnsData>>, Error=ResolverError>>
    where F: FnMut(&str) -> Box<Future<Item=Option<Vec<DnsData>>, Error=ResolverError>> + 'static,
{
    let stream = stream::iter::<_, _, ResolverError>(input.into_iter().map(|x| Ok(x)))
                 .map(move |to_resolve| resolve_fn(&to_resolve))
                 .buffer_unordered(10);
    Box::new(stream)
}

fn main() {
    let domains_src_filename = env::args().nth(1).unwrap();
    let domains_dst_filename = env::args().nth(2).unwrap();
    let hosts_src_filename   = env::args().nth(3).unwrap();
    let hosts_dst_filename   = env::args().nth(4).unwrap();

    let dns_servers = vec![
        "8.8.8.8:53".parse().unwrap(),        // Google primary
        "8.8.4.4:53".parse().unwrap(),        // Google secondary
    ];

    // Synchronously load files
    let (mut domains, mut ips) = (
        load_file(domains_src_filename).unwrap(),
        load_file(hosts_src_filename).unwrap()
    );

    let overall_count = ips.len() + domains.len();
    let mut done_count = 0;

    {
        // Create Tokio Core
        let mut lp = Core::new().unwrap();
        let handle = lp.handle();

        // Create progress mpscs
        let (done_tx, done_rx) = mpsc::channel(1024);

        // Create resolvers with different DNS servers
        let mut resolver1 = TrustDNSResolver::new(dns_servers.clone(), handle.clone(), done_tx.clone());
        let mut resolver2 = TrustDNSResolver::new(dns_servers.clone(), handle.clone(), done_tx);
    
        // Spawn resolvers and move loaded data there
        let domains_future = resolve(ips.clone(), move |item| resolver1.reverse_resolve(item));
        let ips_future = resolve(domains.clone(), move |item| resolver2.resolve(item));


        let domains_collect_future = domains_future.filter(Option::is_some)
                                           .map(Option::unwrap)
                                           .for_each(|vec| 
        {    
            for mut result in vec.into_iter() {
                println!("{:?}", result);
                result.take_name().map(|name|domains.insert(name));
            }
            Ok(())
        });

       /* let ips_collect_future = ips_future.filter(Option::is_some)
                                           .map(Option::unwrap)
                                           .for_each(|vec| 
        {    
            for mut result in vec.into_iter() {
                result.take_ip().map(|ip|ips.insert(ip));
            }
            Ok(())
        });
        */
        
        handle.spawn(done_rx.for_each(move |_| {
            done_count += 1;
            if done_count % 10 == 0 || done_count == overall_count {
                print!("{}/{}\r", done_count, overall_count);
                stdout().flush().unwrap();
            }
            Ok(())
        }));

        //let task = domains_collect_future.join(ips_collect_future);
        let task = domains_collect_future;
        lp.run(task).unwrap();
    }

    write_file(domains.into_iter(), domains_dst_filename).unwrap();
    write_file(ips.into_iter(), hosts_dst_filename).unwrap();
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
