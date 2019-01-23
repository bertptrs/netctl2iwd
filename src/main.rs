#[macro_use]
extern crate clap;

use clap::Arg;

mod convert;
mod networks;

/// Default install location of network files.
const DEFAULT_INSTALL_PATH: &str = "/var/lib/iwd";

fn main() {
    let matches = app_from_crate!()
        .arg(Arg::with_name("input")
            .conflicts_with("dir")
            .required(true)
            .help("Profile files to process")
            .multiple(true))
        .arg(Arg::with_name("output")
            .short("o")
            .long("output-dir")
            .default_value(DEFAULT_INSTALL_PATH))
        .arg(Arg::with_name("dir")
            .help("Directory of profiles to process")
            .conflicts_with("input")
            .long("input-dir")
            .short("i")
            .required(true)
            .takes_value(true))
        .get_matches();

    if let Some(dir) = matches.value_of("dir") {
        println!("Reading profiles from {}", dir);
    } else if let Some(files) = matches.values_of("input") {
        for file in files {
            println!("Reading profile {}", file);
        }
    } else {
        unreachable!("clap should handle this");
    }
}
