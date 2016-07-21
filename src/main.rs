extern crate pcap;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate rustc_serialize;
extern crate argparse;
mod pingnet;
mod client;
mod server;

use argparse::{ArgumentParser, StoreTrue, Store};
use client::CaptureClient;
use server::CaptureServer;
use std::io::{self, Read};


pub trait Runnable {
    fn start(&mut self);
    fn exit(&mut self);
}

fn main() {
    let mut verbose = false;
    let mut post_url = "http://localhost".to_string();
    let mut buffer_size = 10;
    let mut server_mode = false;
    {
        // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("Captures ping replies and sends them, in batches, to a specified URL \
                            using HTTP");
        ap.refer(&mut verbose)
          .add_option(&["-v", "--verbose"], StoreTrue, "Be verbose");
        ap.refer(&mut server_mode)
          .add_option(&["-s", "--server-mode"],
                      StoreTrue,
                      "Start in server mode (default: client mode)");
        ap.refer(&mut post_url)
          .add_option(&["--url"], Store, "URL to send packets to");
        ap.refer(&mut buffer_size)
          .add_option(&["--batchsize"], Store, "Size of each batch (default: 10)");
        ap.parse_args_or_exit();
    }

    let runner: Option<Box<Runnable>>;
    if server_mode {
        runner = Some(Box::new(CaptureServer::new(String::from("0.0.0.0"), 1338)));
    } else {
        runner = Some(Box::new(CaptureClient::new(post_url, buffer_size)));
    }
    let mut runner: Box<Runnable> = runner.unwrap();

    runner.start();
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
    runner.exit();
}
