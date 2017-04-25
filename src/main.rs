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

#[macro_use]
mod macros;
mod resolve;
mod config;
use resolve::*;
use config::*;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::io::{self, Read, Write};
use std::fs::File;
use std::sync::mpsc;
use std::thread;
use std::time::{Instant, Duration};

use std::sync::{Arc, Mutex};
use std::env;
use std::io::stdout;

use clap::{Arg, App};

use log::{LogRecord, LogLevelFilter};
use env_logger::LogBuilder;

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
    let default_config_locations = vec![
        "batch_resolve.toml",
        "$HOME/.config/batch_resolve.toml",
        "/etc/batch_resolve.toml",
    ];

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
                Err(err) => debug!("failed to open default config file {:?}: {}", config_path, err),
                Ok(f) => { 
                    file = Some(f);
                    break
                },
                
            }
        }
        file
    };

    if let Some(mut config_file) = config_file {
        let mut config_str = String::new();
        config_file.read_to_string(&mut config_str).unwrap();
        CONFIG.write().unwrap().parse(&config_str).unwrap_or_else(|e| {
            error!("malformed configuration file: {}", e);
            std::process::exit(1);
        });
    }

    {
        let config = CONFIG.read().unwrap();
        info!("Retries on timeout: {:?}", config.timeout_retries());
        info!("DNS Servers:        {:?}", config.dns_list());
    }
}

struct ResolveState {
    pub result: Arc<Mutex<Vec<String>>>,
    pub out_path: String
}

impl ResolveState {
    pub fn new(out_path: String) -> Self {
        ResolveState {
            result: Arc::default(),
            out_path: out_path,
        }
    }

    pub fn unwrap(self) -> (Vec<String>, String) {
        let result = Arc::try_unwrap(self.result).unwrap().into_inner().unwrap();
        (result, self.out_path)
    }
}

fn main() {
    let (inputs, outputs, qtypes) = process_args();

    let mut overall_count = 0;
    let mut resolve_states = vec![];
    let mut batch = Batch::new();

    for (&qtype, (input, output)) in qtypes.iter().zip(inputs.iter().zip(outputs.into_iter())) {
        let input_data = load_file(input).unwrap_or_else(|err| {
            error!("failed to open {:?}: {}", input, err);
            std::process::exit(1);
        });

        overall_count += input_data.len();

        let rresult = ResolveState::new(output);
        batch.add_task(input_data, rresult.result.clone(), qtype);
        resolve_states.push(rresult);
    }
        
    // Create status output thread and register status callback
    let (status_tx, status_rx) = mpsc::channel::<Status>();
    
    thread::spawn(move || {
        // Print every 100ms
        let mut instant = Instant::now();
        for status in status_rx.iter() {
            if instant.elapsed() > Duration::from_millis(100) {
                let running = format!("{:6} running", status.running);
                let done    = format!("{:6}/{} done", status.done, overall_count);
                let success = format!("{:6}/{} succeded", status.success, overall_count);
                let fail    = format!("{:6}/{} failed", status.fail, overall_count);
                let error   = format!("{:6} errored", status.errored);

                print!("{} {} {} {} {}\r", 
                    running,
                    done,
                    success,
                    fail,
                    error
                );

                stdout().flush().unwrap();

                instant = Instant::now();
            }
        }
    });

    batch.register_status_callback(Box::new(move |status: Status| {
        status_tx.send(status).unwrap(); 
    }));

    // Execute batch job
    batch.run();

    // Merge all data with common output path
    let mut data_sinks = HashMap::new();
    for resolved in resolve_states.into_iter() {
        let (data, path) = resolved.unwrap();
        let entry = data_sinks.entry(path).or_insert(HashSet::new());
        (*entry).extend(data);
    }

    // Merge data into files
    for (path, data) in data_sinks.into_iter() {
        write_file(data, path).unwrap();
    }
}

fn load_file<P: AsRef<Path>>(path: P) -> io::Result<HashSet<String>> {
    let mut buffer = String::new();
    let mut file = File::open(path)?;
    file.read_to_string(&mut buffer)?;
    Ok(buffer.lines().map(String::from).collect())
}

// TODO merge data by output and by query type
fn write_file<'a, I: IntoIterator<Item=String>, P: AsRef<Path>>(data: I, path: P) -> io::Result<()> {
    // Open file for writing
    let mut file = File::create(path)?;

    // Sort and output data
    let mut data = data.into_iter().collect::<Vec<_>>();
    data.sort();
    for item in &data {
        file.write(item.as_bytes())?;
        file.write(b"\n")?;
    }

    Ok(())
}

fn setup_logger(level: LogLevelFilter) {
    let format = |record: &LogRecord| {
        format!("{}: {}\t\t\t", record.level(), record.args())
    };

    let mut builder = LogBuilder::new();
    builder.format(format)
           .filter(Some("batch_resolve"), level);

    if env::var("RUST_LOG").is_ok() {
       builder.parse(&env::var("RUST_LOG").unwrap());
    }

    builder.init().unwrap();
}
