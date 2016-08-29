extern crate pcap;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate rustc_serialize;
extern crate argparse;
mod packet;
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
    let mut client_post_url = "http://localhost:1338/api".to_string();
    let mut client_buffer_size = 10;
    let mut server_port = 1338;
    let mut client_host_identifier = "default".to_string();
    let mut timer: u64 = 0;
    let mut bpf_addon = "".to_string();

    let mut server_mode = false;
    {
        // this block limits scope of borrows by ap.refer() method
        let mut ap = ArgumentParser::new();
        ap.set_description("Captures packets and sends them, in batches, to a specified URL \
                            using HTTP");
        ap.refer(&mut verbose)
          .add_option(&["-v", "--verbose"], StoreTrue, "Be verbose");
        ap.refer(&mut server_mode)
          .add_option(&["-s", "--server-mode"],
                      StoreTrue,
                      "Start in server mode (default: client mode)");
        ap.refer(&mut client_post_url)
          .add_option(&["-u", "--url"],
                      Store,
                      "URL to send packets to (default: http://localhost:1338/api)");
        ap.refer(&mut client_buffer_size)
          .add_option(&["-b", "--batchsize"],
                      Store,
                      "Size of each batch (default: 10)");
        ap.refer(&mut client_host_identifier)
          .add_option(&["-i", "--hostidentifier"],
                      Store,
                      "Identifier that will be added to each request (default: default)");
        ap.refer(&mut server_port)
          .add_option(&["-p", "--port"],
                      Store,
                      "Port to listen on in server mode (default: 1338)");
        ap.refer(&mut timer)
          .add_option(&["-t", "--timer"],
                      Store,
                      "Interval (in seconds) at which packets will be transmitted (if any \
                       packets are in the buffer)");
        ap.refer(&mut bpf_addon)
          .add_option(&["-b", "--bpf"],
                      Store,
                      "Additional packet filter (BPF-format) to use while capturing");
        ap.parse_args_or_exit();
    }

    let timer_opt: Option<u64>;
    if timer == 0 {
        timer_opt = None;
    } else {
        timer_opt = Some(timer);
    }

    let bpf_opt: Option<String>;
    if bpf_addon.len() == 0 {
        bpf_opt = None;
    } else {
        bpf_opt = Some(bpf_addon);
    }

    let runner: Option<Box<Runnable>>;
    if server_mode {
        runner = Some(Box::new(CaptureServer::new(String::from("0.0.0.0"), server_port)));
    } else {
        runner = Some(Box::new(CaptureClient::new(client_post_url,
                                                  client_buffer_size,
                                                  client_host_identifier,
                                                  timer_opt,
                                                  bpf_opt)));
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
