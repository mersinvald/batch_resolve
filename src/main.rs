#[macro_use]
extern crate log;
extern crate env_logger;

#[macro_use]
extern crate lazy_static;
extern crate futures;
extern crate trust_dns;
extern crate tokio_core;

mod resolve;
use resolve::*;

use std::cell::RefCell;
use std::iter::IntoIterator;
use std::iter::Iterator;
use std::collections::HashSet;
use std::path::Path;
use std::io::{self, Read, Write};
use std::fs::File;

use std::rc::Rc;
use std::env;
use std::io::stdout;


fn main() {
    setup_logger();

    let domains_src_filename = env::args().nth(1).unwrap();
    let domains_dst_filename = env::args().nth(2).unwrap();
    let hosts_src_filename   = env::args().nth(3).unwrap();
    let hosts_dst_filename   = env::args().nth(4).unwrap();

    // Synchronously load files
    let (mut domains, mut hosts) = (
        load_file(domains_src_filename).unwrap(),
        load_file(hosts_src_filename).unwrap()
    );

    let overall_count = hosts.len() + domains.len();
    
    // Vectors to store results
    let resolved_domains = Rc::new(RefCell::new(Vec::new()));
    let resolved_hosts = Rc::new(RefCell::new(Vec::new()));

    // Create batch resolver and fill it with tasks
    let mut batch = Batch::new();
    batch.add_task(domains.clone(), resolved_hosts.clone(), QueryType::A);
    batch.add_task(hosts.clone(), resolved_domains.clone(), QueryType::PTR);

    // Create status callback
    batch.register_status_callback(Box::new(move |status: Status| {
        // draw_status(status.done, overall_count as u64, 20);
        print!("{}/{} done, {}/{} succesed, {}/{} failed, {} errored\r", 
            status.done, overall_count,
            status.success, overall_count,
            status.fail, overall_count,
            status.errored
        );
        stdout().flush().unwrap();
    }));

    // Execute batch job
    batch.run();

    // Extract data from Rc<RefCell<_>>
    let resolved_domains = Rc::try_unwrap(resolved_domains).unwrap().into_inner();
    let resolved_hosts   = Rc::try_unwrap(resolved_hosts).unwrap().into_inner();

    // Merge back with the original entries
    for mut domain in resolved_domains.into_iter() {
        if domain.ends_with('.') {
            domain.pop();
        }
        domains.insert(domain);
    }

    for host in resolved_hosts {
        hosts.insert(host);
    }

    // Write files
    write_file(domains, domains_dst_filename).unwrap();
    write_file(hosts, hosts_dst_filename).unwrap();
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

fn setup_logger() {
    env_logger::init().unwrap();
}

fn draw_status(done: u64, all: u64, len: usize) {
    let filled = (done as f64 / all as f64 * len as f64).ceil() as usize;
    print!("[");
    for _ in 0..filled {
        print!("=");
    }
    for _ in filled..len {
        print!(" ");
    }
    print!("]");
}
