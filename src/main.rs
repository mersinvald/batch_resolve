#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate toml;

#[macro_use] extern crate log;
#[macro_use] extern crate clap;
extern crate env_logger;

extern crate futures;
extern crate trust_dns;
extern crate tokio_core;
extern crate crossbeam;  
extern crate num_cpus;                                              
extern crate indicatif;

mod resolve;
mod config;
use resolve::*;
use config::*;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::io::{self, Read, Write};
use std::fs::File;
use std::thread;
use std::time::Duration;

use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use std::env;

use clap::{Arg, App};

use log::{LogRecord, LogLevelFilter};
use env_logger::LogBuilder;

use indicatif::{ProgressBar, ProgressStyle};

fn process_args() -> (Vec<String>, Vec<String>, Vec<QueryType>) {
    let app = App::new("Batch Resolve")
        .about("Fast asynchronous DNS batch resolver")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(Arg::with_name("inputs")
            .help("Input file")
            .short("i")
            .long("in")
            .value_name("INPUT")
            .multiple(true)
            .number_of_values(1))
        .arg(Arg::with_name("outputs")
            .help("Output file")
            .short("o")
            .long("out")
            .value_name("OUTPUT")
            .multiple(true)
            .number_of_values(1))
        .arg(Arg::with_name("queries")
            .help("Query type")
            .short("q")
            .long("query")
            .possible_values(&QueryType::variants())
            .value_name("QUERY_TYPE")
            .multiple(true)
            .number_of_values(1))
        .arg(Arg::with_name("config")
            .help("Sets a custom config file")
            .short("c")
            .long("config")
            .value_name("FILE")
            .takes_value(true))
        .arg(Arg::with_name("verbosity")
            .help("Level of verbosity (-v -vv -vvv)")
            .short("v")
            .multiple(true)
        );

    // Save help message to use later on errors
    let mut help_msg = Vec::new();
    app.write_help(&mut help_msg).unwrap();
    let help_msg = String::from_utf8(help_msg).unwrap();
    
    let matches = app.get_matches();

    // Setup logging and with appropriate  verbosity level
    match matches.occurrences_of("verbosity") {
        0 => setup_logger(LogLevelFilter::Error),
        1 => setup_logger(LogLevelFilter::Warn),
        2 => setup_logger(LogLevelFilter::Info),
        3 => setup_logger(LogLevelFilter::Debug),
        4 | _ => setup_logger(LogLevelFilter::Trace),
    }

    // Get arguments
    let inputs  = values_t!(matches.values_of("inputs"),  String).unwrap_or(vec![]);
    let outputs = values_t!(matches.values_of("outputs"), String).unwrap_or(vec![]);
    let qtypes  = values_t!(matches.values_of("queries"), QueryType).unwrap_or(vec![]);

    // Cardinalities should be the same
    if inputs.len() != outputs.len() || outputs.len() != qtypes.len() || inputs.is_empty() {
        error!("input, output and query arguments number must be the same and non-zero");
        println!("{}", help_msg);
        std::process::exit(1);
    } 

    // Process config 
    process_config(matches.value_of("config"));

    // Return inputs, outputs and query types
    (inputs, outputs, qtypes)
}

fn process_config(arg_path: Option<&str>) {
    // Config locations in priority-descending order
    let default_config_locations =
        vec!["batch_resolve.toml", "$HOME/.config/batch_resolve.toml", "/etc/batch_resolve.toml"];

    let config_file = if let Some(arg_path) = arg_path {
        // Custom config is the only option when it is passed
        info!("Custom config path passed: {:?}", arg_path);
        let file = File::open(arg_path).unwrap_or_else(|error| {
            error!("failed to open custom config file {:?}: {}", arg_path, error);
            std::process::exit(1);
        });
        Some(file)
    } else {
        let mut file = None;
        for config_path in default_config_locations {
            match File::open(config_path) {
                Err(err) => {
                    debug!("failed to open default config file {:?}: {}",
                           config_path,
                           err)
                }
                Ok(f) => {
                    file = Some(f);
                    break;
                }

            }
        }
        file
    };

    // Load config into the static CONFIG entry
    if let Some(mut config_file) = config_file {
        let mut config_str = String::new();
        config_file.read_to_string(&mut config_str).unwrap();
        CONFIG.write().unwrap().parse(&config_str).unwrap_or_else(|e| {
            error!("malformed configuration file: {}", e);
            std::process::exit(1);
        });
    }

    // Info to make sure right config is loaded on startup
    let config = CONFIG.read().unwrap();
    info!("Retries on timeout: {:?}", config.timeout_retries());
    info!("Queries Per Second: {:?}", config.qps());
    info!("DNS Servers:        {:?}", config.dns_list());
}

// mpsc::Receiver of resolve results and output file path
struct ResolveResult {
    pub resolved_rx: ResolvedRx,
    pub out_path: String,
}

impl ResolveResult {
    pub fn new(resolved_rx: ResolvedRx, out_path: String) -> Self {
        ResolveResult {
            resolved_rx,
            out_path,
        }
    }
}

fn main() {
    let (inputs, outputs, qtypes) = process_args();

    let mut overall_count = 0;
    let mut resolve_results = vec![];
    let mut batch = Batch::new();

    for (&qtype, (input, output)) in qtypes.iter().zip(inputs.iter().zip(outputs.into_iter())) {
        let input_data = load_file(input).unwrap_or_else(|err| {
            error!("failed to open {:?}: {}", input, err);
            std::process::exit(1);
        });

        overall_count += input_data.len();

        let (resolved_tx, resolved_rx) = mpsc::channel();
        let rresult = ResolveResult::new(resolved_rx, output);
        batch.add_task(input_data, resolved_tx, qtype);
        resolve_results.push(rresult);
    }

    // Create status output thread and register status callback
    let status = Arc::new(Mutex::new(Status::default()));
    let callback_status = status.clone();

    batch.register_status_callback(Box::new(move |s: Status| { *callback_status.lock().unwrap() = s; }));

    thread::spawn(move || {
        debug!("Starting status printer thread");
        let pb = ProgressBar::new(overall_count as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed}] [{wide_bar:.cyan/blue}] {pos}/{len} ({eta}) | {msg} {spinner:.green}")
            .progress_chars("#>-"));

        let mut s;
        while {
            s = status.lock().unwrap().clone();
            s.done < overall_count as u64
        } {
            let message = format!("{} running | {} failed", s.running, s.fail);
            pb.set_position(s.done);
            pb.set_message(&message);
            thread::sleep(Duration::from_millis(30));
        }

        pb.finish_with_message("done");
        debug!("Terminating status printer thread");
    });

    // Execute batch job
    batch.run();

    // Merge all results with common output pathes
    let mut data_sinks = HashMap::new();
    for resolved in resolve_results {
        let entry = data_sinks.entry(resolved.out_path).or_insert_with(HashSet::new);
        (*entry).extend(resolved.resolved_rx);
    }

    // Merge data into files
    for (path, data) in data_sinks {
        write_file(data, path).unwrap();
    }
}

fn load_file<P: AsRef<Path>>(path: P) -> io::Result<HashSet<String>> {
    let mut buffer = String::new();
    let mut file = File::open(path)?;
    file.read_to_string(&mut buffer)?;
    Ok(buffer.lines().map(String::from).collect())
}

fn write_file<I: IntoIterator<Item = String>, P: AsRef<Path>>(data: I,
                                                              path: P)
                                                              -> io::Result<()> {
    // Open file for writing
    let mut file = File::create(path)?;

    // Sort and output data
    let mut data = data.into_iter().collect::<Vec<_>>();
    data.sort();
    for item in &data {
        file.write_all(item.as_bytes())?;
        file.write_all(b"\n")?;
    }

    Ok(())
}

fn setup_logger(level: LogLevelFilter) {
    let format = |record: &LogRecord| format!("{}: {}\t\t\t", record.level(), record.args());

    let mut builder = LogBuilder::new();
    builder.format(format).filter(Some("batch_resolve"), level);

    if env::var("RUST_LOG").is_ok() {
        builder.parse(&env::var("RUST_LOG").unwrap());
    }

    builder.init().unwrap();
}
