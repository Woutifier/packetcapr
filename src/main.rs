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

fn main() {
    let (tx, rx) = channel();

    let t_capture = start_capture(tx);
    let t_transmit = start_transmit(rx);

    t_capture.join().expect("Capture thread failed to exit without errors");
    t_transmit.join().expect("Transmit thread failed to exit without errors");
}

fn start_transmit(rx: Receiver<PingPacket>) -> std::thread::JoinHandle<()> {
    let t_transmit = thread::spawn(move || {
        debug!("[t_transmit] Transmit thread started");
        let mut buf = VecDeque::new();
        let client = Client::new();
        loop {
            debug!("[t_capture] Transmitting data");
            let data = rx.recv().unwrap();
            buf.push_back(data);

            if buf.len() >= 2 {
                println!("Collected some packets... sending!");
                {
                    let collected_packets = buf.iter().collect::<Vec<&PingPacket>>();
                    let encoded_packets = &json::encode(&collected_packets).unwrap();
                    client.post("http://localhost:1338/")
                          .body(encoded_packets)
                          .send()
                          .expect("Could not send HTTP-post request");
                }
                buf.clear();
            }
        }
    });
    t_transmit
}

fn prepare_capture() -> Capture<pcap::Active> {
    let main_device = Device::lookup().unwrap();
    let mut cap: Capture<pcap::Active> = Capture::from_device(main_device)
                                             .unwrap()
                                             .promisc(true)
                                             .snaplen(5000)
                                             .open()
                                             .unwrap();
    cap.filter("icmp[icmptype] == icmp-echo").unwrap();
    cap
}


fn start_capture<'a>(tx: Sender<PingPacket>) -> std::thread::JoinHandle<()> {
    let t_capture = thread::spawn(move || {
        let mut cap = prepare_capture();
        debug!("[t_capture] Capture thread started");
        while let Ok(packet) = cap.next() {
            debug!("[t_capture] Packet received");
            println!("{:?}", packet);
            let pp = PingPacket::from(packet);
            tx.send(pp).unwrap();
        }
    });
    t_capture
}
