extern crate pcap;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate rustc_serialize;
extern crate argparse;
mod pingnet;
mod client;

// use argparse::{ArgumentParser, StoreTrue, Store};
use client::CaptureClient;
use std::io::{self, Read};

fn main() {
   let mut client = CaptureClient::new(String::from("http://localhost:1338/"), 10);

   client.start();

    println!("Process is running. Type q<enter> to quit.");
    loop {
        let mut buffer = [0; 1];
        io::stdin().read_exact(&mut buffer).expect("Error while reading from stdin");
        let letter = String::from_utf8_lossy(&buffer);
        if letter == "q" {
            break;
        }
    }
    println!("Exiting...");
    client.exit();
}

