extern crate pcap;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate rustc_serialize;
extern crate argparse;
mod pingnet;

use pcap::{Device, Capture};
use std::thread;
use hyper::Client;
use std::sync::mpsc::{channel, Sender, Receiver};
use rustc_serialize::json;
use std::collections::VecDeque;
// use argparse::{ArgumentParser, StoreTrue, Store};
use pingnet::pingnet::PingPacket;
use std::io::{self, Read};

fn main() {
    let (tx_packets, rx_packets) = channel();

    let tx_poison = tx_packets.clone();
    let t_capture = start_capture_thread(tx_packets);
    let t_transmit = start_transmit_thread(rx_packets);

    println!("Process is running. Type q<enter> to quit.");
    loop {
        let mut buffer = [0; 1];
        io::stdin().read_exact(&mut buffer);
        let letter = String::from_utf8_lossy(&buffer);
        if letter == "q" {
            break;
        }
    }
    println!("Exiting...");
    tx_poison.send(None).unwrap();

    t_transmit.join().expect("Transmit thread failed to exit without errors");
}

fn start_transmit_thread(rx: Receiver<Option<PingPacket>>) -> std::thread::JoinHandle<()> {
    let t_transmit = thread::spawn(move || {
        debug!("[t_transmit] Transmit thread started");
        let mut buf = VecDeque::new();
        loop {
            debug!("[t_capture] Transmitting data");
            let data = rx.recv().unwrap();

            if data.is_some() {
                buf.push_back(data.unwrap());

                if buf.len() >= 10 {
                    if http_send_packets(&buf).is_ok() {
                        buf.clear();
                    }
                }
            } else {
                http_send_packets(&buf);
                break;
            }
        }
    });
    t_transmit
}

fn start_capture_thread<'a>(tx: Sender<Option<PingPacket>>) -> std::thread::JoinHandle<()> {
    let t_capture = thread::spawn(move || {
        let mut cap = prepare_capture();
        debug!("[t_capture] Capture thread started");
        while let Ok(packet) = cap.next() {
            debug!("[t_capture] Packet received");
            println!("{:?}", packet);
            let pp = PingPacket::from(packet);
            tx.send(Some(pp)).unwrap();
        }
    });
    t_capture
}

fn http_send_packets(buffer: &VecDeque<PingPacket>) -> Result<hyper::client::Response, hyper::Error> {
    let client = Client::new();
    let collected_packets = buffer.iter().collect::<Vec<&PingPacket>>();
    let encoded_packets = &json::encode(&collected_packets).unwrap();
    let result = client.post("http://localhost:1338/")
            .body(encoded_packets)
            .send();
    result
}

fn prepare_capture() -> Capture<pcap::Active> {
    let main_device = Device::lookup().unwrap();
    let mut cap: Capture<pcap::Active> = Capture::from_device(main_device)
                                             .unwrap()
                                             .promisc(true)
                                             .snaplen(5000)
                                             .open()
                                             .unwrap();
    cap.filter("icmp[icmptype] == icmp-echoreply").unwrap();
    cap
}


